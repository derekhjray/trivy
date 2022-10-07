package tomcat

import (
	"context"
	"encoding/xml"
	"errors"
	"gitee.com/anesec/ferret/secrets/templates"
	stypes "gitee.com/anesec/ferret/secrets/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/password"
	"io"
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

func (ts *tomcatScanner) Scan(ctx context.Context, file *stypes.File) ([]*stypes.WeakPassword, error) {
	if file == nil || file.Content == nil {
		return nil, nil
	}

	weaknesses, err := ts.enumerate(ctx, file.Content, file.Path, "")
	if err != nil && errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}

	return weaknesses, nil
}

func (ts *tomcatScanner) enumerate(ctx context.Context, r io.Reader, target string, artifact interface{}) ([]*stypes.WeakPassword, error) {
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
		if pass, err = templates.Enumerate(ctx, templates.Pair(user.Name, user.Password)); err != nil {
			switch e := err.(type) {
			case *templates.WeakError:
				weakness := &stypes.WeakPassword{
					Service:  ts.Name(),
					Target:   target,
					User:     user.Name,
					Password: pass,
					Type:     e.Type(),
					Reason:   e.Error(),
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
