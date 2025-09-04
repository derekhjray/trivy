package password

import (
	"context"
	"os"
	"strings"

	stypes "gitee.com/anesec/ferret/secrets/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/samber/lo"
)

func init() {
	analyzer.RegisterAnalyzer(&passwordAnalyzer{})
}

const version = 1

var (
	SSHScanner    = types.Scanner(stypes.SSHScanner)
	RedisScanner  = types.Scanner(stypes.RedisScanner)
	TomcatScanner = types.Scanner(stypes.TomcatScanner)
)

var AllScanners = types.Scanners{SSHScanner, RedisScanner, TomcatScanner}

var (
	weakPasswordConfigs = map[types.Scanner][]string{
		RedisScanner:  {"redis.conf"},
		SSHScanner:    {"etc/shadow"},
		TomcatScanner: {"tomcat-users.xml"},
	}
)

// passwordAnalyzer calculates SHA-256 for each binary not managed by package managers (called unpackaged binaries)
// so that it can search for SBOM attestation in post-handler.
type passwordAnalyzer struct {
	scanner types.Scanner
	configs []string
	policy  string
	tenant  int64
}

func (a *passwordAnalyzer) Init(opts analyzer.AnalyzerOptions) error {
	a.scanner = ""
	a.configs = nil
	a.policy = opts.WeakPasswordOption.Policy
	scanner := types.Scanner(opts.WeakPasswordOption.Scanner)

	if !AllScanners.Enabled(scanner) {
		return nil
	}

	a.scanner = scanner
	if len(opts.WeakPasswordOption.Configs) > 0 {
		a.configs = opts.WeakPasswordOption.Configs
	} else {
		a.configs = weakPasswordConfigs[a.scanner]
	}

	a.tenant = opts.WeakPasswordOption.TenantId

	return nil
}

func (a *passwordAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	if a.scanner == "" || len(a.configs) == 0 || a.policy == "" {
		// skip password scanning if not initialized
		return nil, nil
	}

	opts := &stypes.Options{
		File: &stypes.File{
			Path:    input.FilePath,
			Content: input.Content,
			Info:    input.Info,
			Scanner: string(a.scanner),
		},
		Templates: a.policy,
		TenantId:  a.tenant,
	}

	weaknesses, err := Scan(ctx, opts)
	if err != nil {
		return nil, err
	}

	if len(weaknesses) > 0 {
		result := &analyzer.AnalysisResult{WeakPasswords: make([]ftypes.WeakPassword, 0, len(weaknesses))}
		for _, weakness := range weaknesses {
			result.WeakPasswords = append(result.WeakPasswords, ftypes.WeakPassword{WeakPassword: *weakness})
		}

		return result, nil
	}

	return nil, nil
}

func (a *passwordAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	if a.scanner == "" || len(a.configs) == 0 || a.policy == "" {
		return false
	}

	if lo.ContainsBy(a.configs, func(item string) bool {
		return strings.HasSuffix(filePath, item)
	}) {
		return true
	}

	return false
}

func (a *passwordAnalyzer) Type() analyzer.Type {
	return analyzer.TypeWeakPassword
}

func (a *passwordAnalyzer) Version() int {
	return version
}
