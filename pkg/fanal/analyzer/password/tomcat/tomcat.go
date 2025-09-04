package tomcat

import (
	"context"
	"encoding/xml"
	"errors"
	"io"

	"gitee.com/anesec/ferret/secrets/templates"
	stypes "gitee.com/anesec/ferret/secrets/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/password"
)

func init() {
	password.RegisterScaner(&tomcatScanner{})
}

type Users struct {
	XMLName xml.Name `xml:"tomcat-users"`
	Version string   `xml:"version,attr"`
	Users   []*User  `xml:"user"`
}

type User struct {
	XMLName  xml.Name `xml:"user"`
	Name     string   `xml:"username,attr"`
	Password string   `xml:"password,attr"`
}

type tomcatScanner struct {
}

func (ts *tomcatScanner) Name() string {
	return stypes.TomcatScanner
}

func (ts *tomcatScanner) Scan(ctx context.Context, file *stypes.File, options []templates.Option) ([]*stypes.WeakPassword, error) {
	if file == nil || file.Content == nil {
		return nil, nil
	}

	weaknesses, err := ts.enumerate(ctx, file.Content, file.Path, "", options)
	if err != nil && errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}

	return weaknesses, nil
}

func (ts *tomcatScanner) enumerate(ctx context.Context, r io.Reader, target string, _ interface{}, options []templates.Option) ([]*stypes.WeakPassword, error) {
	var (
		users Users
		pass  string
		err   error
	)

	if err = xml.NewDecoder(r).Decode(&users); err != nil {
		return nil, err
	}

	weaknesses := make([]*stypes.WeakPassword, 0, 8)
	for _, user := range users.Users {
		opts := append(options, templates.Pair(user.Name, user.Password))
		if pass, err = templates.Enumerate(ctx, opts...); err != nil {
			var we *templates.WeakError
			switch {
			case errors.As(err, &we):
				weakness := &stypes.WeakPassword{
					Service:  ts.Name(),
					Target:   target,
					User:     user.Name,
					Password: pass,
					Type:     we.Type(),
					Reason:   we.Error(),
				}

				weaknesses = append(weaknesses, weakness)
			default:
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return nil, err
				}
			}
		}
	}

	return weaknesses, nil
}
