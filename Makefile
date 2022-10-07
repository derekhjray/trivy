TARGET=trivy
SOURCES=$(shell find . -type f -name "*.go")
VERSION=$(shell git describe --tags)

$(TARGET): $(SOURCES)
	CGO_ENABLED=0 go build -ldflags "-extldflags '-static' -s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=${VERSION}" -o $@ ./cmd/trivy

.PHONY: clean
clean:
	@rm -f $(TARGET)