package flag

import (
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	WeakPasswordScannerFlag = Flag[string]{
		Name:       "weak-password-scanner",
		ConfigName: "weakpass.weak-password-scanner",
		Default:    "",
		Usage:      "specify required weak password scanner(sshd,redis,tomcat)",
	}

	WeakPasswordPolicyFlag = Flag[string]{
		Name:       "weak-password-policy",
		ConfigName: "weakpass.weak-password-policy",
		Default:    "",
		Usage:      "weak password analyzer policy filepath",
	}

	RedisConfigsFlag = Flag[[]string]{
		Name:       "redis-configs",
		ConfigName: "weakpass.redis-configs",
		Default:    []string{"redis.conf"},
		Usage:      "specify redis configure file, filepath or basename",
	}

	TomcatConfigsFlag = Flag[[]string]{
		Name:       "tomcat-configs",
		ConfigName: "weakpass.tomcat-configs",
		Default:    []string{"tomcat-users.xml"},
		Usage:      "specify tomcat configure file, filepath or basename",
	}
)

// WeakPasswordFlagGroup composes common printer flag structs used for commands providing weak-password scanning.
type WeakPasswordFlagGroup struct {
	WeakPasswordScanner *Flag[string]

	WeakPasswordPolicy *Flag[string]

	// scanner configurations
	RedisConfigs  *Flag[[]string]
	TomcatConfigs *Flag[[]string]
}

type WeakPasswordOptions struct {
	WeakPasswordScanner types.Scanner

	WeakPasswordPolicy string

	TenantId int64

	// scanner configurations
	RedisConfigs  []string
	TomcatConfigs []string
}

func NewWeakPasswordFlagGroup() *WeakPasswordFlagGroup {
	return &WeakPasswordFlagGroup{
		WeakPasswordScanner: WeakPasswordScannerFlag.Clone(),
		WeakPasswordPolicy:  WeakPasswordPolicyFlag.Clone(),
		RedisConfigs:        RedisConfigsFlag.Clone(),
		TomcatConfigs:       TomcatConfigsFlag.Clone(),
	}
}

func (f *WeakPasswordFlagGroup) Name() string {
	return "WeakPassword"
}

func (f *WeakPasswordFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.WeakPasswordScanner,
		f.WeakPasswordPolicy,
		f.RedisConfigs,
		f.TomcatConfigs,
	}
}

func (f *WeakPasswordFlagGroup) ToOptions() (WeakPasswordOptions, error) {
	return WeakPasswordOptions{
		WeakPasswordScanner: types.Scanner(f.WeakPasswordScanner.Value()),
		WeakPasswordPolicy:  f.WeakPasswordPolicy.Value(),
		RedisConfigs:        f.RedisConfigs.Value(),
		TomcatConfigs:       f.TomcatConfigs.Value(),
	}, nil
}
