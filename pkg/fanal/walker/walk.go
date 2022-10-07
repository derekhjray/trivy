package walker

import (
	"os"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

const (
	defaultSizeThreshold    = int64(8) << 20   // 8MiB
	slowSizeThreshold       = int64(100) << 10 // 10KiB
	minMemoryUsageThreshold = int64(300 << 20) // 300MiB
	maxMemoryUsageThreshold = int64(400 << 20) // 400MiB, do not cache file in memory
	baseMemoryUsage         = int64(200 << 20) // 200MiB, assumed basic memory usage without scanning jobs
)

var defaultSkipDirs = []string{
	"**/.git",
	"proc",
	"sys",
	"dev",
}

type Option struct {
	SkipFiles []string
	SkipDirs  []string
	Parallel  int
	Threshold int64
}

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error
type RequiredFunc func(filePath string, info os.FileInfo) bool
