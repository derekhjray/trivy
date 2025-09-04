package redis

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
	password.RegisterScaner(&redisScanner{})
}

type redisScanner struct {
}

func (rs *redisScanner) Name() string {
	return stypes.RedisScanner
}

func (rs *redisScanner) Scan(ctx context.Context, file *stypes.File, options []templates.Option) ([]*stypes.WeakPassword, error) {
	if file == nil || file.Content == nil {
		return nil, nil
	}

	weakness, err := rs.enumerate(ctx, file.Content, file.Path, "", options)
	if err != nil || weakness == nil {
		if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return nil, err
		}

		return nil, nil
	}

	return []*stypes.WeakPassword{weakness}, nil
}

func (rs *redisScanner) enumerate(ctx context.Context, r io.Reader, target, _ string, options []templates.Option) (*stypes.WeakPassword, error) {
	var (
		conf *config
		err  error
	)

	conf, err = rs.parseConfigFile(r)
	if err != nil {
		return nil, err
	}

	localsets := map[string]struct{}{
		"127.0.0.1": {},
		"::1":       {},
		"localhost": {},
	}

	if conf.password == "" {
		if conf.protected {
			remote := false
			for _, host := range conf.binds {
				if _, ok := localsets[host]; !ok {
					remote = true
					break
				}
			}

			if !remote {
				return nil, nil
			}
		}

		return &stypes.WeakPassword{
			Service: rs.Name(),
			Target:  target,
			Type:    int(stypes.TypeEmpty),
			Reason:  "requirepass option not set, but not protected mode or allow remote access",
		}, nil
	}

	options = append(options, templates.Pair("", conf.password))
	var pass string
	pass, err = templates.Enumerate(ctx, options...)
	if err != nil {
		var we *templates.WeakError
		switch {
		case errors.As(err, &we):
			return &stypes.WeakPassword{
				Service:  rs.Name(),
				Target:   target,
				Password: pass,
				Type:     we.Type(),
				Reason:   we.Error(),
			}, nil
		default:
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
		}
	}

	return nil, err
}

type config struct {
	binds     []string
	password  string
	protected bool
}

func (rs *redisScanner) parseConfigFile(r io.Reader) (*config, error) {
	conf := &config{
		binds: make([]string, 0, 4),
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "bind":
			for _, field := range fields[1:] {
				field = strings.TrimSpace(field)
				if len(field) == 0 || field[0] == '#' {
					continue
				}
				conf.binds = append(conf.binds, field)
			}
		case "protected-mode":
			conf.protected = strings.ToLower(strings.TrimSpace(fields[1])) == "yes"
		case "requirepass":
			conf.password = strings.TrimSpace(fields[1])
		}
	}

	return conf, nil
}
