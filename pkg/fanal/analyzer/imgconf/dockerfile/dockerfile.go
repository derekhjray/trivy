package dockerfile

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/mapfs"
	"github.com/aquasecurity/trivy/pkg/misconf"
)

var disabledChecks = []misconf.DisabledCheck{
	{
		ID: "DS016", Scanner: string(analyzer.TypeHistoryDockerfile),
		Reason: "See https://github.com/aquasecurity/trivy/issues/7368",
	},
}

const analyzerVersion = 1

func init() {
	analyzer.RegisterConfigAnalyzer(analyzer.TypeHistoryDockerfile, newHistoryAnalyzer)
}

type historyAnalyzer struct {
	scanner *misconf.Scanner
}

func newHistoryAnalyzer(opts analyzer.ConfigAnalyzerOptions) (analyzer.ConfigAnalyzer, error) {
	opts.MisconfScannerOption.DisabledChecks = append(opts.MisconfScannerOption.DisabledChecks, disabledChecks...)
	s, err := misconf.NewScanner(detection.FileTypeDockerfile, opts.MisconfScannerOption)
	if err != nil {
		return nil, xerrors.Errorf("misconfiguration scanner error: %w", err)
	}
	return &historyAnalyzer{
		scanner: s,
	}, nil
}

func (a *historyAnalyzer) Analyze(ctx context.Context, input analyzer.ConfigAnalysisInput) (*analyzer.
	ConfigAnalysisResult, error) {
	if input.Config == nil {
		return nil, nil
	}

	dockerfile := new(bytes.Buffer)
	var userFound bool
	argRe := regexp.MustCompile(`^\|(\d+)\s+`)
	baseLayerIndex := image.GuessBaseImageIndex(input.Config.History)
	for i := baseLayerIndex + 1; i < len(input.Config.History); i++ {
		h := input.Config.History[i]
		var createdBy = strings.TrimSpace(strings.TrimSuffix(h.CreatedBy, "# buildkit"))

		if matches := argRe.FindStringSubmatch(createdBy); len(matches) == 2 {
			processed := false
			if argN, err := strconv.Atoi(matches[1]); err == nil {
				if parts := strings.SplitN(createdBy, " ", argN+2); len(parts) == argN+2 {
					createdBy = parts[argN+1]
					processed = true
				}
			}

			if !processed {
				if index := strings.Index(createdBy, "/bin/sh -c"); index > 0 {
					createdBy = createdBy[index:]
				}
			}
		}

		if strings.HasPrefix(createdBy, "/bin/sh -c #(nop)") {
			// Instruction other than RUN
			createdBy = strings.TrimPrefix(createdBy, "/bin/sh -c #(nop)")
		}

		if strings.HasPrefix(createdBy, "/bin/sh -c") {
			// RUN instruction
			createdBy = strings.ReplaceAll(createdBy, "/bin/sh -c", "RUN")
		}

		if strings.HasPrefix(createdBy, "RUN /bin/sh -c") {
			// buildkit instructions
			// COPY ./foo /foo # buildkit
			// ADD ./foo.txt /foo.txt # buildkit
			// RUN /bin/sh -c ls -hl /foo # buildkit
			createdBy = strings.ReplaceAll(createdBy, "RUN /bin/sh -c", "RUN")
		}

		createdBy = strings.TrimSpace(createdBy)

		switch {
		case strings.HasPrefix(createdBy, "USER"):
			// USER instruction
			userFound = true
		case strings.HasPrefix(createdBy, "LABEL") || strings.HasPrefix(createdBy, "ENV"):
			parts := strings.Split(createdBy, "=")
			buf := bytes.NewBuffer(make([]byte, 0, len(createdBy)+8))
			for j := 0; j < len(parts); j++ {
				if j == 0 {
					buf.WriteString(parts[j])
					continue
				}

				buf.WriteByte('=')

				spaces := strings.Count(parts[j], " ")
				if j+1 == len(parts) {
					if spaces > 0 {
						buf.WriteByte('"')
						buf.WriteString(parts[j])
						buf.WriteByte('"')
					} else {
						buf.WriteString(parts[j])
					}
					continue
				}

				if spaces > 1 {
					if index := strings.LastIndex(parts[j], " "); index > 0 {
						buf.WriteByte('"')
						buf.WriteString(parts[j][:index])
						buf.WriteByte('"')
						buf.WriteString(parts[j][index:])
						continue
					}
				}

				buf.WriteString(parts[j])
			}

			createdBy = buf.String()
		case strings.HasPrefix(createdBy, "HEALTHCHECK"):
			// Healthcheck field may nil on containerd runtime
			if input.Config.Config.Healthcheck == nil {
				continue
			}

			// HEALTHCHECK instruction
			var interval, timeout, startPeriod, retries, command string
			if input.Config.Config.Healthcheck.Interval != 0 {
				interval = fmt.Sprintf("--interval=%s ", input.Config.Config.Healthcheck.Interval)
			}
			if input.Config.Config.Healthcheck.Timeout != 0 {
				timeout = fmt.Sprintf("--timeout=%s ", input.Config.Config.Healthcheck.Timeout)
			}
			if input.Config.Config.Healthcheck.StartPeriod != 0 {
				startPeriod = fmt.Sprintf("--start-period=%s ", input.Config.Config.Healthcheck.StartPeriod)
			}
			if input.Config.Config.Healthcheck.Retries != 0 {
				retries = fmt.Sprintf("--retries=%d ", input.Config.Config.Healthcheck.Retries)
			}
			command = strings.Join(input.Config.Config.Healthcheck.Test, " ")
			command = strings.ReplaceAll(command, "CMD-SHELL", "CMD")
			createdBy = fmt.Sprintf("HEALTHCHECK %s%s%s%s%s", interval, timeout, startPeriod, retries, command)
		}

		dockerfile.WriteString(strings.TrimSpace(createdBy) + "\n")
	}

	if !userFound && input.Config.Config.User != "" {
		user := fmt.Sprintf("USER %s", input.Config.Config.User)
		dockerfile.WriteString(user)
	}

	fsys := mapfs.New()
	if err := fsys.WriteVirtualFile("Dockerfile", dockerfile.Bytes(), 0600); err != nil {
		return nil, xerrors.Errorf("mapfs write error: %w", err)
	}

	misconfs, err := a.scanner.Scan(ctx, fsys)
	if err != nil {
		return nil, xerrors.Errorf("history scan error: %w", err)
	}
	// The result should be a single element as it passes one Dockerfile.
	if len(misconfs) != 1 {
		return nil, nil
	}

	return &analyzer.ConfigAnalysisResult{
		Misconfiguration: &misconfs[0],
	}, nil
}

func (a *historyAnalyzer) Required(_ types.OS) bool {
	return true
}

func (a *historyAnalyzer) Type() analyzer.Type {
	return analyzer.TypeHistoryDockerfile
}

func (a *historyAnalyzer) Version() int {
	return analyzerVersion
}
