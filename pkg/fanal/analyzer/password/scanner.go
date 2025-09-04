package password

import (
	"context"
	"sync"

	"gitee.com/anesec/ferret/secrets/templates"
	stypes "gitee.com/anesec/ferret/secrets/types"
)

var (
	scanners = map[string]Scanner{}
	locker   sync.RWMutex
)

type Scanner interface {
	Name() string
	Scan(context.Context, *stypes.File, []templates.Option) ([]*stypes.WeakPassword, error)
}

func RegisterScaner(scanner Scanner) {
	locker.Lock()
	scanners[scanner.Name()] = scanner
	locker.Unlock()
}

func Scan(ctx context.Context, options *stypes.Options) ([]*stypes.WeakPassword, error) {
	var (
		weaknesses []*stypes.WeakPassword
		err        error
	)

	opts := make([]templates.Option, 0, 16)
	if options.Templates != "" {
		opts = append(opts, templates.Template(options.Templates))
	}

	if options.MinDistance > 0 {
		opts = append(opts, templates.Distance(options.MinDistance))
	}

	if options.MinLength > 0 {
		opts = append(opts, templates.Length(options.MinLength))
	}

	if options.MinUniqueChars > 0 {
		opts = append(opts, templates.UniqueChars(options.MinUniqueChars))
	}

	if options.Digit {
		opts = append(opts, templates.MustContainDigit())
	}

	if options.Symbol {
		opts = append(opts, templates.MustContainSymbol())
	}

	opts = append(opts, templates.Tenant(options.TenantId))

	if err = templates.Load(ctx, opts...); err != nil {
		return nil, err
	}
	defer templates.Unload()

	locker.RLock()
	defer locker.RUnlock()

	if options.File != nil {
		for _, scanner := range scanners {
			if scanner.Name() == options.File.Scanner {
				weaknesses, err = scanner.Scan(ctx, options.File, opts)
				break
			}
		}
	}

	if err != nil {
		return nil, err
	}

	return weaknesses, nil
}
