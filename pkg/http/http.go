package http

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"gitee.com/anesec/mobius/types"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultDBFile = "trivy.db"
)

var (
	ErrNotUpdated = xerrors.New("vulnerability database not updated, skipping download")
)

type Option func(*Artifact)

func WithDownloadTime(tm time.Time) Option {
	return func(artifact *Artifact) {
		artifact.lastDownloadTime = tm
	}
}

func WithToken(token string) Option {
	return func(artifact *Artifact) {
		artifact.token = token
	}
}

func NewArtifact(url string, quiet bool, options ...Option) (*Artifact, error) {
	af := &Artifact{
		url:      url,
		quiet:    quiet,
		filename: defaultDBFile,
	}

	for _, option := range options {
		option(af)
	}

	if af.token == "" {
		return nil, errors.New("no token provided")
	}

	tenantId := os.Getenv(types.TenantId)
	shardId := os.Getenv(types.ShardId)
	if tenantId != "" && shardId != "" {
		af.url = fmt.Sprintf("%s?TenantID=%s&ShardID=%s", af.url, tenantId, shardId)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	transport.DialContext = (&net.Dialer{
		Timeout:   5 * time.Minute,
		KeepAlive: time.Second * 30,
	}).DialContext

	af.client = &http.Client{Transport: transport}

	return af, nil
}

type Artifact struct {
	url              string
	filename         string
	lastDownloadTime time.Time
	modified         bool
	token            string
	quiet            bool

	client *http.Client
}

func (af *Artifact) NeedUpdate() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := af.head(ctx)
	if err != nil && errors.Is(err, ErrNotUpdated) {
		return false, nil
	}

	return true, err
}

func (af *Artifact) Download(ctx context.Context, dir string) (err error) {
	var (
		contentLength int64
		cancel        context.CancelFunc
	)

	if _, ok := ctx.Deadline(); !ok {
		ctx, cancel = context.WithTimeout(ctx, time.Minute*5)
		defer cancel()
	}

	dbPath := db.Path(dir)

	if _, err = os.Stat(dbPath); os.IsNotExist(err) {
		af.lastDownloadTime = time.Time{}
	}

	if contentLength, err = af.head(ctx); err != nil {
		if errors.Is(err, ErrNotUpdated) {
			return nil
		}

		return err
	}

	if contentLength <= 0 {
		return xerrors.Errorf("invalid vulnerabity database file size: %d", contentLength)
	}

	if err = os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return xerrors.Errorf("unable to create vulnerability database directory, %v", err)
	}

	var (
		file, out    *os.File
		tmpFile      = dbPath + ".dat"
		offset, size int64
	)

	if file, err = os.OpenFile(tmpFile, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0644); err != nil {
		return xerrors.Errorf("unable to create vulnerability database temporary file, %v", err)
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(tmpFile)
		if err != nil && af.validate(dir, err) {
			err = nil
		}
	}()

	chunkSize := contentLength

	for chunkSize > 0 {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			return
		default:
		}

		if size, err = af.download(ctx, file, offset, chunkSize); err != nil {
			if size == -1 {
				err = xerrors.Errorf("unable to download vulnerability database, %v", err)
				return
			}

			logrus.Debugf("Try download vulnerability database file failed, %v", err)
			time.Sleep(time.Second)
			continue
		}

		offset += size
		chunkSize = contentLength - offset
	}

	if _, err = file.Seek(0, io.SeekStart); err != nil {
		err = xerrors.Errorf("unable to reset vulnerability database file offset, %v", err)
		return
	}

	gr, err := gzip.NewReader(file)
	if err != nil {
		err = xerrors.Errorf("unable to create vulnerability database gzip reader, %v", err)
		return
	}

	if out, err = os.OpenFile(dbPath, os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0644); err != nil {
		_ = os.Remove(dbPath)
		err = xerrors.Errorf("unable to create vulnerability database file, %v", err)
		return
	}

	if _, err = io.Copy(out, gr); err != nil {
		_ = os.Remove(dbPath)
		err = xerrors.Errorf("unable to decompress vulnerability database, %v", err)
	}

	return
}

func (af *Artifact) download(ctx context.Context, file *os.File, offset, chunk int64) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, af.url, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Add("Authorization", af.token)
	req.Header.Add("User-Agent", "metrics")
	req.Header.Add("Accept", "application/gzip")
	req.Header.Add("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+chunk-1))

	resp, err := af.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return 0, af.normalizeHttpError(resp)
	}

	contentLength := resp.Header.Get("Content-Length")
	size, err := strconv.ParseInt(contentLength, 10, 64)
	if err != nil {
		return 0, xerrors.Errorf("invalid content length, %v", err)
	}

	if contentType := resp.Header.Get("Content-Type"); strings.Contains(contentType, "application/json") {
		var result struct {
			Code    int
			Message string
		}

		if err = json.NewDecoder(resp.Body).Decode(&result); err == nil {
			err = fmt.Errorf("%s(%d)", result.Message, result.Code)
		}

		return -1, err
	}

	return io.CopyN(file, resp.Body, size)
}

func (af *Artifact) head(ctx context.Context) (int64, error) {

	logrus.Debugf("Checking vulnerability database file metadata...")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, af.url, nil)
	if err != nil {
		return 0, xerrors.Errorf("unable to check vulnerability database, %v", err)
	}

	if af.token != "" {
		req.Header.Add("Authorization", af.token)
	}

	req.Header.Add("User-Agent", "metrics")
	req.Header.Add("Accept", "application/gzip")
	if !af.lastDownloadTime.IsZero() {
		req.Header.Add("If-Modified-Since", af.lastDownloadTime.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	}

	resp, err := af.client.Do(req)
	if err != nil {
		return 0, xerrors.Errorf("unable to check vulnerability database, %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		return 0, xerrors.Errorf("unable to check vulnerability database, %v", af.normalizeHttpError(resp))
	}

	lastModified, err := time.Parse(http.TimeFormat, resp.Header.Get("Last-Modified"))
	if err == nil {
		af.lastDownloadTime = lastModified
	}

	af.modified = resp.StatusCode != http.StatusNotModified

	if !af.modified {
		return 0, ErrNotUpdated
	}

	contentLength := resp.Header.Get("Content-Length")
	size, err := strconv.Atoi(contentLength)
	if err != nil {
		return 0, xerrors.Errorf("unable to check vulnerability database, invalid 'Content-Length: %s', %v", contentLength, err)
	}

	if size < 10240 {
		resp.StatusCode = http.StatusNoContent
		return -1, xerrors.Errorf("unable to check vulnerability database, %v", af.normalizeHttpError(resp))
	}

	return int64(size), nil
}

func (af *Artifact) normalizeHttpError(resp *http.Response) (err error) {
	if resp == nil {
		return errors.New("empty http response")
	}

	if contentType := resp.Header.Get("Content-Type"); strings.Contains(contentType, "application/json") {
		var result struct {
			Code    int
			Message string
		}

		if err = json.NewDecoder(resp.Body).Decode(&result); err == nil {
			err = fmt.Errorf("%s(%d)", result.Message, result.Code)
		}
	} else {
		err = errors.New(http.StatusText(resp.StatusCode))
	}

	return err
}

func (af *Artifact) validate(dir string, reason error) (valid bool) {
	var (
		info os.FileInfo
		err  error
	)

	if info, err = os.Stat(db.Path(dir)); err == nil && info.Size() > 300<<20 {
		logrus.Warnf("Download vulnerability database failed, %v", reason)
		logrus.Infof("Try using previous downloaded vulnerability database instead.")
		return true
	}

	return
}

type repository struct {
	url string
}

// Context accesses the Repository context of the reference.
func (repo *repository) Context() name.Repository {
	return name.Repository{}
}

// Identifier accesses the type-specific portion of the reference.
func (repo *repository) Identifier() string {
	return repo.url
}

// Name is the fully-qualified reference name.
func (repo *repository) Name() string {
	return "anesec"
}

// Scope is the scope needed to access this reference.
func (repo *repository) Scope(scope string) string {
	return scope
}

func (repo *repository) String() string {
	return repo.url
}

func NewRepository(repo string) name.Reference {
	return &repository{url: repo}
}
