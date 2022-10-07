package jar

import (
	"context"
	"errors"
	"gitee.com/anesec/ostrich/pkg/client"
	"gitee.com/anesec/ostrich/pkg/errdefs"
	otypes "gitee.com/anesec/ostrich/pkg/types"
	"github.com/sirupsen/logrus"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/parallel"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeJar, newJavaLibraryAnalyzer)
}

const version = 1

var requiredExtensions = []string{
	".jar",
	".war",
	".ear",
	".par",
}

// javaLibraryAnalyzer analyzes jar/war/ear/par files
type javaLibraryAnalyzer struct {
	parallel       int
	largeFileLimit int64
	client         client.JavaDB
	once           sync.Once
}

func newJavaLibraryAnalyzer(options analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &javaLibraryAnalyzer{
		parallel:       options.Parallel,
		largeFileLimit: int64(options.LargeFileLimit),
	}, nil
}

func (a *javaLibraryAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	// TODO: think about the sonatype API and "--offline"
	var err error
	if !input.Options.Offline {
		// do not create javadb client if offline mode
		a.once.Do(func() {
			logrus.Debugf("Initialize Java dependency validation driver")
			if a.client, err = client.NewJavaDBClient(client.URL(os.Getenv(otypes.OstrichJavaDBPolicy)), client.Insecure()); err != nil {
				logrus.Warnf("Unable to initialize Java dependency validation driver, %v", err)
				logrus.Warnf("Skip Java dependency validation while parsing Java packages")
				return
			}
			logrus.Debugf("Initialize Java dependency validation driver done")
		})
	}

	// It will be called on each JAR file
	onFile := func(path string, info fs.FileInfo, r xio.ReadSeekerAt) (*types.Application, error) {
		p := jar.NewParser(a, jar.WithSize(info.Size()), jar.WithFilePath(path), jar.WithOffline(a.client == nil))
		return language.ParsePackage(types.Jar, path, r, p, input.Options.FileChecksum)
	}

	var apps []types.Application
	onResult := func(app *types.Application) error {
		if app == nil {
			return nil
		}
		apps = append(apps, *app)
		return nil
	}

	if err = parallel.WalkDir(ctx, input.FS, ".", a.parallel, onFile, onResult); err != nil {
		logrus.Debugf("Skip scanning java package, %v", err)
		//return nil, xerrors.Errorf("walk dir error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a *javaLibraryAnalyzer) Required(filePath string, info os.FileInfo) bool {
	if a.largeFileLimit > 0 && info.Size() > a.largeFileLimit {
		return false
	}

	ext := filepath.Ext(filePath)
	for _, required := range requiredExtensions {
		if strings.EqualFold(ext, required) {
			return true
		}
	}
	return false
}

func (a *javaLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJar
}

func (a *javaLibraryAnalyzer) Version() int {
	return version
}

func (a *javaLibraryAnalyzer) Exists(groupID, artifactID string) (bool, error) {
	if a.client != nil {
		return a.client.Exists(groupID, artifactID)
	}

	return false, jar.ArtifactNotFoundErr
}

func (a *javaLibraryAnalyzer) SearchBySHA1(sha1 string) (jar.Properties, error) {
	if a.client != nil {
		properties, err := a.client.SearchBySHA1(sha1)
		if err != nil {
			if errors.Is(err, errdefs.ErrArtifactNotFound) {
				err = jar.ArtifactNotFoundErr
			}

			return jar.Properties{}, err
		}

		return jar.Properties{
			GroupID:    properties.GroupID,
			ArtifactID: properties.ArtifactID,
			Version:    properties.Version,
			FilePath:   properties.FilePath,
		}, nil
	}

	return jar.Properties{}, jar.ArtifactNotFoundErr
}

func (a *javaLibraryAnalyzer) SearchByArtifactID(artifactID, version string) (string, error) {
	if a.client != nil {
		groupId, err := a.client.SearchByArtifactID(artifactID, version)
		if err != nil && errors.Is(err, errdefs.ErrArtifactNotFound) {
			err = jar.ArtifactNotFoundErr
		}

		return groupId, err
	}

	return "", jar.ArtifactNotFoundErr
}
