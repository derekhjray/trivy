package walker

import (
	"archive/tar"
	"context"
	"errors"
	"github.com/aquasecurity/trivy/pkg/parallel"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

const (
	opq string = ".wh..wh..opq"
	wh  string = ".wh."
)

var parentDir = ".." + utils.PathSeparator

type LayerTar struct {
	skipFiles []string
	skipDirs  []string

	fileSizeThreshold       int64
	maxMemoryUsageThreshold int64
	minMemoryUsageThreshold int64

	workers    parallel.Pool
	maxWorkers int
	once       sync.Once

	gc struct {
		timestamp time.Time
		running   uint32
	}
}

func NewLayerTar(opt Option) *LayerTar {
	var (
		maxMemoryThreshold = maxMemoryUsageThreshold
		minMemoryThreshold = minMemoryUsageThreshold
	)

	if opt.Threshold > 0 && opt.Threshold <= minMemoryUsageThreshold {
		opt.Threshold = minMemoryUsageThreshold
	} else if opt.Threshold <= 0 {
		// using default configures
		opt.Threshold = maxMemoryUsageThreshold
	}

	maxMemoryThreshold = opt.Threshold
	minMemoryThreshold = (opt.Threshold-baseMemoryUsage)/2 + baseMemoryUsage

	logrus.Debugf("Image layer walker memory usage threshold: maximum=%d minimum=%d", maxMemoryThreshold, minMemoryThreshold)

	return &LayerTar{
		skipFiles:               utils.CleanSkipPaths(opt.SkipFiles),
		skipDirs:                utils.CleanSkipPaths(opt.SkipDirs),
		maxWorkers:              lo.Ternary(opt.Parallel < 4, 4, opt.Parallel),
		fileSizeThreshold:       lo.Ternary(opt.Parallel <= 1, slowSizeThreshold, defaultSizeThreshold),
		maxMemoryUsageThreshold: maxMemoryThreshold,
		minMemoryUsageThreshold: minMemoryThreshold,
	}
}

func (w *LayerTar) Walk(ctx context.Context, layer v1.Layer, requiredFn RequiredFunc, analyzeFn WalkFunc) ([]string, []string, error) {
	var (
		opqDirs, whFiles, skippedDirs []string
		rc                            io.ReadCloser
		retries                       int
		err                           error
	)

	w.once.Do(func() {
		w.workers = parallel.NewPool(ctx, parallel.MaxGoroutines(w.maxWorkers))
	})

	analyzedFiles := make(map[string]struct{})
	defer func() {
		if rc != nil {
			_ = rc.Close()
		}
	}()

	base := baseJob{analyze: analyzeFn}

retry:
	if retries > 0 {
		if rc != nil {
			// close previous opened layer reader
			_ = rc.Close()
			rc = nil
		}
		// retry 5 second later
		logrus.Debugf("Detect temporary network error, analyze current layer again in 5 seconds")
		time.Sleep(time.Second * 5)
	}

	if rc, err = layer.Uncompressed(); err != nil {
		return nil, nil, xerrors.Errorf("failed to get the layer content: %w", err)
	}

	var hdr *tar.Header
	tr := tar.NewReader(rc)
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		if err = base.Error(); err != nil {
			return nil, nil, err
		}

		if hdr, err = tr.Next(); err == io.EOF {
			break
		} else if err != nil {
			if w.shouldRetry(retries, err) {
				retries++
				goto retry
			}

			return nil, nil, xerrors.Errorf("failed to extract the archive: %w", err)
		}

		// filepath.Clean cannot be used since tar file paths should be OS-agnostic.
		filePath := path.Clean(hdr.Name)
		filePath = strings.TrimLeft(filePath, "/")
		fileDir, fileName := path.Split(filePath)

		// e.g. etc/.wh..wh..opq
		if opq == fileName {
			opqDirs = append(opqDirs, fileDir)
			continue
		}
		// etc/.wh.hostname
		if strings.HasPrefix(fileName, wh) {
			name := strings.TrimPrefix(fileName, wh)
			fpath := path.Join(fileDir, name)
			whFiles = append(whFiles, fpath)
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if utils.SkipPath(filePath, w.skipDirs) {
				skippedDirs = append(skippedDirs, filePath)
				continue
			}
		case tar.TypeReg:
			if utils.SkipPath(filePath, w.skipFiles) {
				continue
			}
		// symlinks and hardlinks have no content in reader, skip them
		default:
			continue
		}

		if underSkippedDir(filePath, skippedDirs) {
			continue
		}

		if hdr.Size == 0 {
			// skip empty file
			continue
		}

		if _, analyzed := analyzedFiles[filePath]; analyzed {
			continue
		}

		info := hdr.FileInfo()
		if !requiredFn(filePath, info) {
			continue
		}

		// A regular file will reach here.
		if err = w.processFile(filePath, tr, info, &base); err != nil {
			if w.shouldRetry(retries, err) {
				retries++
				goto retry
			}

			return nil, nil, xerrors.Errorf("failed to process the file: %w", err)
		}

		analyzedFiles[filePath] = struct{}{}
	}

	base.Wait()

	if err = base.Error(); err != nil {
		return nil, nil, err
	}

	return opqDirs, whFiles, nil
}

func (w *LayerTar) processFile(filePath string, tr *tar.Reader, fi fs.FileInfo, base *baseJob) error {
	size, threshold := fi.Size(), w.fileSizeThreshold
	usage, err := utils.GetMemoryUsage()
	if usage > w.maxMemoryUsageThreshold {
		// scanner process using too much memory, do not cache small file in memory
		threshold = 1
	} else if usage > w.minMemoryUsageThreshold || err != nil {
		threshold = slowSizeThreshold
	}

	if threshold != w.fileSizeThreshold && time.Since(w.gc.timestamp) > time.Second*30 {
		if atomic.CompareAndSwapUint32(&w.gc.running, 0, 1) {
			go func() {
				runtime.GC()
				w.gc.timestamp = time.Now()
				atomic.StoreUint32(&w.gc.running, 0)
			}()
		}
	}

	cf := newCachedFile(size, tr, threshold)

	if _, err = cf.Open(); err != nil {
		return xerrors.Errorf("failed to open the file: %w", err)
	}

	base.Add(1)

	job := acquire()
	job.baseJob = base
	job.cf = cf
	job.filePath = filePath
	job.info = fi

	w.workers.Run(context.TODO(), job)

	return nil
}

func (w *LayerTar) Stop() {
	if w.workers != nil {
		w.workers.Close()
	}
}

func (w *LayerTar) shouldRetry(times int, reason error) bool {
	if reason == nil || times >= 3 {
		return false
	}

	return errors.Is(reason, io.ErrUnexpectedEOF) || errors.Is(reason, syscall.ECONNRESET)
}

func underSkippedDir(filePath string, skipDirs []string) bool {
	for _, skipDir := range skipDirs {
		rel, err := filepath.Rel(skipDir, filePath)
		if err != nil {
			return false
		}
		if !strings.HasPrefix(rel, parentDir) {
			return true
		}
	}
	return false
}

var (
	jobs sync.Pool
)

func acquire() *analyzeJob {
	if job, ok := jobs.Get().(*analyzeJob); ok && job != nil {
		return job
	}

	return &analyzeJob{}
}

func release(job *analyzeJob) {
	if job != nil {
		job.reset()
		jobs.Put(job)
	}
}

type baseJob struct {
	sync.WaitGroup

	analyze WalkFunc
	errors  atomic.Pointer[error]
}

func (base *baseJob) Error() error {
	if err := base.errors.Load(); err != nil {
		return *err
	}

	return nil
}

func (base *baseJob) SetError(err error) {
	base.errors.Store(&err)
}

type analyzeJob struct {
	*baseJob

	cf       *cachedFile
	filePath string
	info     fs.FileInfo
}

func (job *analyzeJob) reset() {
	job.cf = nil
	job.filePath = ""
	job.info = nil
	job.baseJob = nil
}

func (job *analyzeJob) Run(ctx context.Context) {
	defer func() {
		job.cf.Clean()
		job.Done()
		release(job)
	}()

	select {
	case <-ctx.Done():
		return
	default:
	}

	if err := job.Error(); err != nil {
		// error detected for previous job
		return
	}

	if err := job.analyze(job.filePath, job.info, job.cf.Open); err != nil {
		job.SetError(err)
	}
}
