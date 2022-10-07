package types

import (
	"time"

	"github.com/samber/lo"
)

type OS struct {
	Family OSType `json:",omitempty"`
	Name   string `json:",omitempty"`
	Eosl   bool   `json:"EOSL,omitempty"`

	// This field is used for enhanced security maintenance programs such as Ubuntu ESM, Debian Extended LTS.
	Extended bool `json:"extended,omitempty"`
}

func (o *OS) Detected() bool {
	return o.Family != ""
}

// Merge merges OS version and enhanced security maintenance programs
func (o *OS) Merge(newOS OS) {
	if lo.IsEmpty(newOS) {
		return
	}

	switch {
	// OLE also has /etc/redhat-release and it detects OLE as RHEL by mistake.
	// In that case, OS must be overwritten with the content of /etc/oracle-release.
	// There is the same problem between Debian and Ubuntu.
	case o.Family == RedHat, o.Family == Debian:
		*o = newOS
	default:
		if o.Family == "" {
			o.Family = newOS.Family
		}
		if o.Name == "" {
			o.Name = newOS.Name
		}
		// Ubuntu has ESM program: https://ubuntu.com/security/esm
		// OS version and esm status are stored in different files.
		// We have to merge OS version after parsing these files.
		if o.Extended || newOS.Extended {
			o.Extended = true
		}
	}
}

type User struct {
	ID   int    `json:",omitempty"`
	GID  int    `json:",omitempty"`
	Name string `json:",omitempty"`
}

type Group struct {
	ID   int    `json:",omitempty"`
	Name string `json:",omitempty"`
}

type FileInfo struct {
	Name       string `json:",omitempty"`
	User       string `json:",omitempty"`
	Group      string `json:",omitempty"`
	Mode       string `json:",omitempty"`
	Permission uint32 `json:",omitempty"`
	Size       int64  `json:",omitempty"`
	MD5        string `json:",omitempty"`
	CreateTime int64  `json:",omitempty"`
	ModifyTime int64  `json:",omitempty"`
	AccessTime int64  `json:",omitempty"`
}

type Repository struct {
	Family  OSType `json:",omitempty"`
	Release string `json:",omitempty"`
}

type Layer struct {
	Digest    string `json:",omitempty"`
	DiffID    string `json:",omitempty"`
	CreatedBy string `json:",omitempty"`
}

type PackageInfo struct {
	FilePath string   `json:",omitempty"`
	Packages Packages `json:",omitempty"`
}

type Application struct {
	// e.g. bundler and pipenv
	Type LangType `json:",omitempty"`

	// Lock files have the file path here, while each package metadata do not have
	FilePath string `json:",omitempty"`

	// Packages is a list of lang-specific packages
	Packages Packages `json:",omitempty"`
}

type File struct {
	Type    string `json:",omitempty"`
	Path    string `json:",omitempty"`
	Content []byte `json:",omitempty"`
}

// ArtifactInfo is stored in cache
type ArtifactInfo struct {
	SchemaVersion int       `json:",omitempty"`
	Architecture  string    `json:",omitempty"`
	Created       time.Time `json:",omitempty"`
	DockerVersion string    `json:",omitempty"`
	OS            string    `json:",omitempty"`

	// Misconfiguration holds misconfiguration in container image config
	Misconfiguration *Misconfiguration `json:",omitempty"`

	// Secret holds secrets in container image config such as environment variables
	Secret *Secret `json:",omitempty"`

	// HistoryPackages are packages extracted from RUN instructions
	HistoryPackages Packages `json:",omitempty"`
}

// BlobInfo is stored in cache
type BlobInfo struct {
	SchemaVersion int `json:",omitempty"`

	// Layer information
	Digest        string   `json:",omitempty"`
	DiffID        string   `json:",omitempty"`
	CreatedBy     string   `json:",omitempty"`
	OpaqueDirs    []string `json:",omitempty"`
	WhiteoutFiles []string `json:",omitempty"`

	// Analysis result
	OS                OS                 `json:",omitempty"`
	Users             []User             `json:",omitempty"`
	Groups            []Group            `json:",omitempty"`
	Repository        *Repository        `json:",omitempty"`
	PackageInfos      []PackageInfo      `json:",omitempty"`
	Applications      []Application      `json:",omitempty"`
	Misconfigurations []Misconfiguration `json:",omitempty"`
	Secrets           []Secret           `json:",omitempty"`
	WeakPasswords     []WeakPassword     `json:",omitempty"`
	Licenses          []LicenseFile      `json:",omitempty"`

	// Red Hat distributions have build info per layer.
	// This information will be embedded into packages when applying layers.
	// ref. https://redhat-connect.gitbook.io/partner-guide-for-adopting-red-hat-oval-v2/determining-common-platform-enumeration-cpe
	BuildInfo *BuildInfo `json:",omitempty"`

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []CustomResource `json:",omitempty"`
}

// ArtifactDetail represents the analysis result.
type ArtifactDetail struct {
	OS                OS                 `json:",omitempty"`
	Repository        *Repository        `json:",omitempty"`
	Packages          Packages           `json:",omitempty"`
	Applications      []Application      `json:",omitempty"`
	Misconfigurations []Misconfiguration `json:",omitempty"`
	Secrets           []Secret           `json:",omitempty"`
	WeakPasswords     []WeakPassword     `json:",omitempty"`
	Licenses          []LicenseFile      `json:",omitempty"`
	Users             []User             `json:",omitempty"`
	Groups            []Group            `json:",omitempty"`

	// ImageConfig has information from container image config
	ImageConfig ImageConfigDetail

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []CustomResource `json:",omitempty"`
}

// ImageConfigDetail has information from container image config
type ImageConfigDetail struct {
	// Packages are packages extracted from RUN instructions in history
	Packages []Package `json:",omitempty"`

	// Misconfiguration holds misconfigurations in container image config
	Misconfiguration *Misconfiguration `json:",omitempty"`

	// Secret holds secrets in container image config
	Secret *Secret `json:",omitempty"`

	// WeakPasswords holds weak passwords in container image config
	WeakPasswords []WeakPassword
}

// ToBlobInfo is used to store a merged layer in cache.
func (a *ArtifactDetail) ToBlobInfo() BlobInfo {
	return BlobInfo{
		SchemaVersion: BlobJSONSchemaVersion,
		OS:            a.OS,
		Repository:    a.Repository,
		PackageInfos: []PackageInfo{
			{
				FilePath: "merged", // Set a dummy file path
				Packages: a.Packages,
			},
		},
		Applications:      a.Applications,
		Misconfigurations: a.Misconfigurations,
		Secrets:           a.Secrets,
		Licenses:          a.Licenses,
		CustomResources:   a.CustomResources,
	}
}

// CustomResource holds the analysis result from a custom analyzer.
// It is for extensibility and not used in OSS.
type CustomResource struct {
	Type     string      `json:",omitempty"`
	FilePath string      `json:",omitempty"`
	Layer    Layer       `json:",omitempty"`
	Data     any		 `json:",omitempty"`
}
