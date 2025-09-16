package sshd

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"

	"gitee.com/anesec/ferret/secrets/templates"
	stypes "gitee.com/anesec/ferret/secrets/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/password"
)

func init() {
	password.RegisterScaner(&sshScanner{})
}

type sshScanner struct {
}

func (ss *sshScanner) Name() string {
	return stypes.SSHScanner
}

func (ss *sshScanner) Scan(ctx context.Context, file *stypes.File, options []templates.Option) ([]*stypes.WeakPassword, error) {
	if file == nil || file.Content == nil {
		return nil, nil
	}

	weaknesses, err := ss.enumerate(ctx, file.Content, file.Path, "", options)
	if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return nil, err
	}

	return weaknesses, nil
}

func (ss *sshScanner) enumerate(ctx context.Context, r io.Reader, target string, _ interface{}, options []templates.Option) ([]*stypes.WeakPassword, error) {
	var (
		pass       string
		weaknesses []*stypes.WeakPassword
		err        error
	)

	weaknesses = make([]*stypes.WeakPassword, 0, 4)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		text := scanner.Text()
		fields := strings.FieldsFunc(text, func(r rune) bool {
			return r == ':'
		})

		if len(fields) <= 2 || len(fields[1]) < 8 || fields[1][0] != '$' {
			continue
		}

		opts := append(options, templates.Pair(fields[0], fields[1]), templates.Shadow())
		pass, err = templates.Enumerate(ctx, opts...)
		if err != nil {
			var we *templates.WeakError
			switch {
			case errors.As(err, &we):
				weakness := &stypes.WeakPassword{
					Service:  ss.Name(),
					Target:   target,
					Rule:     we.Rule(),
					User:     fields[0],
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
