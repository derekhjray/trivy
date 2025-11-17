package remote

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/image/registry"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/version/app"
)

type Descriptor = remote.Descriptor

func isTemporary(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}

	if te, ok := err.(interface{ Temporary() bool }); ok && te.Temporary() {
		return true
	}

	return false
}

var (
	retryPredicate = func(err error) bool {
		// Various failure modes here, as we're often reading from and writing to
		// the network.
		if isTemporary(err) ||
			errors.Is(err, io.ErrUnexpectedEOF) ||
			errors.Is(err, io.EOF) ||
			errors.Is(err, syscall.EPIPE) ||
			errors.Is(err, syscall.ECONNRESET) ||
			errors.Is(err, syscall.ECONNREFUSED) ||
			errors.Is(err, syscall.ECONNABORTED) ||
			errors.Is(err, syscall.ETIMEDOUT) ||
			errors.Is(err, net.ErrClosed) {
			log.Debugf("Retrying image registry service, %v", err)
			return true
		}

		return false
	}

	// Try this ten times, total 90 seconds.
	retryBackoff = remote.Backoff{
		Duration: 3000 * time.Millisecond,
		Factor:   1.45,
		Jitter:   0.3,
		Steps:    5,
	}

	retryStatusCodes = []int{
		http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
		499, // nginx-specific, client closed request
		522, // Cloudflare-specific, connection timeout
		524,
	}

	resumableBackoff = remote.Backoff{
		Duration: 2000 * time.Millisecond,
		Factor:   1.65,
		Jitter:   0.3,
		Steps:    5,
	}
)

// Get is a wrapper of google/go-containerregistry/pkg/v1/remote.Get
// so that it can try multiple authentication methods.
func Get(ctx context.Context, ref name.Reference, option types.RegistryOptions) (*Descriptor, error) {
	tr, err := httpTransport(option)
	if err != nil {
		return nil, xerrors.Errorf("failed to create http transport: %w", err)
	}

	var errs error
	// Try each authentication method until it succeeds
	for _, authOpt := range authOptions(ctx, ref, option) {
		remoteOpts := []remote.Option{
			remote.WithTransport(tr),
			remote.WithContext(ctx),
			remote.WithResumable(),
			remote.WithResumableBackoff(resumableBackoff),
			remote.WithRetryBackoff(retryBackoff),
			remote.WithRetryPredicate(retryPredicate),
			remote.WithRetryStatusCodes(retryStatusCodes...),
			authOpt,
		}

		if option.Platform.Platform != nil {
			p, err := resolvePlatform(ref, option.Platform, remoteOpts)
			if err != nil {
				return nil, xerrors.Errorf("platform error: %w", err)
			}
			// Don't pass platform when the specified image is single-arch.
			if p.Platform != nil {
				remoteOpts = append(remoteOpts, remote.WithPlatform(*p.Platform))
			}
		}

		desc, err := remote.Get(ref, remoteOpts...)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		if option.Platform.Force {
			if err = satisfyPlatform(desc, lo.FromPtr(option.Platform.Platform)); err != nil {
				return nil, err
			}
		}
		return desc, nil
	}

	// No authentication succeeded
	return nil, errs
}

// Image is a wrapper of google/go-containerregistry/pkg/v1/remote.Image
// so that it can try multiple authentication methods.
func Image(ctx context.Context, ref name.Reference, option types.RegistryOptions) (v1.Image, error) {
	tr, err := httpTransport(option)
	if err != nil {
		return nil, xerrors.Errorf("failed to create http transport: %w", err)
	}

	var errs error
	// Try each authentication method until it succeeds
	for _, authOpt := range authOptions(ctx, ref, option) {
		remoteOpts := []remote.Option{
			remote.WithTransport(tr),
			remote.WithContext(ctx),
			remote.WithResumable(),
			remote.WithRetryBackoff(retryBackoff),
			remote.WithRetryPredicate(retryPredicate),
			remote.WithRetryStatusCodes(retryStatusCodes...),
			authOpt,
		}
		index, err := remote.Image(ref, remoteOpts...)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}
		return index, nil
	}

	// No authentication succeeded
	return nil, errs
}

// Referrers is a wrapper of google/go-containerregistry/pkg/v1/remote.Referrers
// so that it can try multiple authentication methods.
func Referrers(ctx context.Context, d name.Digest, option types.RegistryOptions) (v1.ImageIndex, error) {
	tr, err := httpTransport(option)
	if err != nil {
		return nil, xerrors.Errorf("failed to create http transport: %w", err)
	}

	var errs error
	// Try each authentication method until it succeeds
	for _, authOpt := range authOptions(ctx, d, option) {
		remoteOpts := []remote.Option{
			remote.WithTransport(tr),
			remote.WithContext(ctx),
			remote.WithResumable(),
			remote.WithRetryBackoff(retryBackoff),
			remote.WithRetryPredicate(retryPredicate),
			remote.WithRetryStatusCodes(retryStatusCodes...),
			authOpt,
		}
		index, err := remote.Referrers(d, remoteOpts...)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}
		return index, nil
	}

	// No authentication succeeded
	return nil, errs
}

func httpTransport(option types.RegistryOptions) (http.RoundTripper, error) {
	d := &net.Dialer{
		Timeout: 10 * time.Minute,
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = d.DialContext
	tr.ForceAttemptHTTP2 = os.Getenv("FORCE_ATTEMPT_HTTP2") == "true"
	tr.DisableKeepAlives = os.Getenv("HTTP_KEEP_ALIVE") != "true"
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: option.Insecure}

	if len(option.ClientCert) != 0 && len(option.ClientKey) != 0 {
		cert, err := tls.X509KeyPair(option.ClientCert, option.ClientKey)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	userAgent := os.Getenv("HTTP_USER_AGENT")
	if userAgent == "" {
		userAgent = fmt.Sprintf("trivy/%s", app.Version())
	}

	tripper := transport.NewUserAgent(tr, userAgent)
	return tripper, nil
}

func authOptions(ctx context.Context, ref name.Reference, option types.RegistryOptions) []remote.Option {
	var opts []remote.Option
	for _, cred := range option.Credentials {
		opts = append(opts, remote.WithAuth(&authn.Basic{
			Username: cred.Username,
			Password: cred.Password,
		}))
	}

	domain := ref.Context().RegistryStr()
	token := registry.GetToken(ctx, domain, option)
	if !lo.IsEmpty(token) {
		opts = append(opts, remote.WithAuth(&token))
	}

	switch {
	case option.RegistryToken != "":
		bearer := authn.Bearer{Token: option.RegistryToken}
		return []remote.Option{remote.WithAuth(&bearer)}
	default:
		// Use the keychain anyway at the end
		opts = append(opts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
		return opts
	}
}

// resolvePlatform resolves the OS platform for a given image reference.
// If the platform has an empty OS, the function will attempt to find the first OS
// in the image's manifest list and return the platform with the detected OS.
// It ignores the specified platform if the image is not multi-arch.
func resolvePlatform(ref name.Reference, p types.Platform, options []remote.Option) (types.Platform, error) {
	if p.OS != "" {
		return p, nil
	}

	// OS wildcard, implicitly pick up the first os found in the image list.
	// e.g. */amd64
	d, err := remote.Get(ref, options...)
	if err != nil {
		return types.Platform{}, xerrors.Errorf("image get error: %w", err)
	}
	switch d.MediaType {
	case v1types.OCIManifestSchema1, v1types.DockerManifestSchema2:
		// We want an index but the registry has an image, not multi-arch. We just ignore "--platform".
		log.Debug("Ignore `--platform` as the image is not multi-arch")
		return types.Platform{}, nil
	case v1types.OCIImageIndex, v1types.DockerManifestList:
		// These are expected.
	}

	index, err := d.ImageIndex()
	if err != nil {
		return types.Platform{}, xerrors.Errorf("image index error: %w", err)
	}

	m, err := index.IndexManifest()
	if err != nil {
		return types.Platform{}, xerrors.Errorf("remote index manifest error: %w", err)
	}
	if len(m.Manifests) == 0 {
		log.Debug("Ignore '--platform' as the image is not multi-arch")
		return types.Platform{}, nil
	}
	if m.Manifests[0].Platform != nil {
		newPlatform := p.DeepCopy()
		// Replace with the detected OS
		// e.g. */amd64 => linux/amd64
		newPlatform.OS = m.Manifests[0].Platform.OS

		// Return the platform with the found OS
		return types.Platform{
			Platform: newPlatform,
			Force:    p.Force,
		}, nil
	}
	return types.Platform{}, nil
}

func satisfyPlatform(desc *remote.Descriptor, platform v1.Platform) error {
	img, err := desc.Image()
	if err != nil {
		return err
	}
	c, err := img.ConfigFile()
	if err != nil {
		return err
	}
	if !lo.FromPtr(c.Platform()).Satisfies(platform) {
		return xerrors.Errorf("the specified platform not found")
	}
	return nil
}
