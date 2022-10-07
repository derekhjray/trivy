package gemspec

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const specNewStr = "Gem::Specification.new"

var (
	// Capture the variable name
	// e.g. Gem::Specification.new do |s|
	//      => s
	newVarRegexp = regexp.MustCompile(`\|(?P<var>.*)\|`)

	// Capture the value of "name"
	// e.g. s.name = "async".freeze
	//      => "async".freeze
	nameRegexp = regexp.MustCompile(`\.name\s*=\s*(?P<name>\S+)`)

	// Capture the value of "version"
	// e.g. s.version = "1.2.3"
	//      => "1.2.3"
	versionRegexp = regexp.MustCompile(`\.version\s*=\s*(?P<version>\S+)`)

	// Capture the value of "license"
	// e.g. s.license = "MIT"
	//      => "MIT"
	licenseRegexp = regexp.MustCompile(`\.license\s*=\s*(?P<license>\S+)`)

	// Capture the value of "licenses"
	// e.g. s.license = ["MIT".freeze, "BSDL".freeze]
	//      => "MIT".freeze, "BSDL".freeze
	licensesRegexp = regexp.MustCompile(`\.licenses\s*=\s*\[(?P<licenses>.+)\]`)

	// Capture the value of "license"
	// e.g. s.license = "MIT"
	//      => "MIT"
	authorRegexp = regexp.MustCompile(`\.author\s*=\s*(?P<author>\S+)`)

	// Capture the value of "licenses"
	// e.g. s.license = ["MIT".freeze, "BSDL".freeze]
	//      => "MIT".freeze, "BSDL".freeze
	authorsRegexp = regexp.MustCompile(`\.authors\s*=\s*\[(?P<authors>.+)\]`)
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) (pkgs []ftypes.Package, deps []ftypes.Dependency, err error) {
	var newVar, name, version, license, author string

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, specNewStr) {
			newVar = findSubString(newVarRegexp, line, "var")
		}

		if newVar == "" {
			continue
		}

		// Capture name, version, license, and licenses
		switch {
		case strings.HasPrefix(line, fmt.Sprintf("%s.name", newVar)):
			// https://guides.rubygems.org/specification-reference/#name
			name = findSubString(nameRegexp, line, "name")
			name = trim(name)
		case strings.HasPrefix(line, fmt.Sprintf("%s.version", newVar)):
			// https://guides.rubygems.org/specification-reference/#version
			version = findSubString(versionRegexp, line, "version")
			version = trim(version)
		case strings.HasPrefix(line, fmt.Sprintf("%s.licenses", newVar)):
			// https://guides.rubygems.org/specification-reference/#licenses=
			license = findSubString(licensesRegexp, line, "licenses")
			license = parseLicenses(license)
		case strings.HasPrefix(line, fmt.Sprintf("%s.license", newVar)):
			// https://guides.rubygems.org/specification-reference/#license=
			license = findSubString(licenseRegexp, line, "license")
			license = trim(license)
		case strings.HasPrefix(line, fmt.Sprintf("%s.authors", newVar)):
			author = findSubString(authorsRegexp, line, "authors")
			author = parseAuthors(author)
		case strings.HasPrefix(line, fmt.Sprintf("%s.author", newVar)):
			author = findSubString(authorRegexp, line, "author")
			author = trim(author)
		}

		// No need to iterate the loop anymore
		if name != "" && version != "" && license != "" && author != "" {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, xerrors.Errorf("failed to parse gemspec: %w", err)
	}

	if name == "" || version == "" {
		return nil, nil, xerrors.New("failed to parse gemspec")
	}

	return []ftypes.Package{
		{
			Name:       name,
			Version:    version,
			Licenses:   licensing.SplitLicenses(license),
			Maintainer: author,
		},
	}, nil, nil
}

func findSubString(re *regexp.Regexp, line, name string) string {
	m := re.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	return m[re.SubexpIndex(name)]
}

// Trim single quotes, double quotes and ".freeze"
// e.g. "async".freeze => async
func trim(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".freeze")
	return strings.Trim(s, `'"`)
}

func parseLicenses(s string) string {
	// e.g. `"Ruby".freeze, "BSDL".freeze`
	//      => {"\"Ruby\".freeze", "\"BSDL\".freeze"}
	ss := strings.Split(s, ",")

	// e.g. {"\"Ruby\".freeze", "\"BSDL\".freeze"}
	//      => {"Ruby", "BSDL"}
	var licenses []string
	for _, l := range ss {
		licenses = append(licenses, trim(l))
	}

	return strings.Join(licenses, ", ")
}

func parseAuthors(s string) string {
	ss := strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || r == ','
	})

	authors := make([]string, 0, len(ss))
	for _, a := range ss {
		authors = append(authors, trim(a))
	}

	return strings.Join(authors, ", ")
}
