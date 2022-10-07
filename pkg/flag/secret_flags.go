package flag

const size256k = 256 << 10

var (
	SecretConfigFlag = Flag[string]{
		Name:       "secret-config",
		ConfigName: "secret.config",
		Default:    "trivy-secret.yaml",
		Usage:      "specify a path to config file for secret scanning",
	}

	MaxFileSizeFlag = Flag[int]{
		Name:       "max-filesize",
		ConfigName: "secret.max-filesize",
		Default:    size256k,
		Usage:      "specify maximum filesize for secret scanning",
	}
)

type SecretFlagGroup struct {
	SecretConfig *Flag[string]
	MaxFileSize  *Flag[int]
}

type SecretOptions struct {
	SecretConfigPath string
	MaxFileSize      int
}

func NewSecretFlagGroup() *SecretFlagGroup {
	return &SecretFlagGroup{
		SecretConfig: SecretConfigFlag.Clone(),
		MaxFileSize:  MaxFileSizeFlag.Clone(),
	}
}

func (f *SecretFlagGroup) Name() string {
	return "Secret"
}

func (f *SecretFlagGroup) Flags() []Flagger {
	return []Flagger{f.SecretConfig, f.MaxFileSize}
}

func (f *SecretFlagGroup) ToOptions() (SecretOptions, error) {
	if err := parseFlags(f); err != nil {
		return SecretOptions{}, err
	}

	return SecretOptions{
		SecretConfigPath: f.SecretConfig.Value(),
		MaxFileSize:      f.MaxFileSize.Value(),
	}, nil
}
