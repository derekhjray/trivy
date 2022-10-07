package utils

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

var (
	buffers sync.Pool
)

func acquire() *bytes.Buffer {
	if v, ok := buffers.Get().(*bytes.Buffer); ok {
		return v
	}

	return bytes.NewBuffer(make([]byte, 0, 1024))
}

func release(v *bytes.Buffer) {
	if v != nil {
		v.Reset()
		buffers.Put(v)
	}
}

func GetMemoryUsage() (int64, error) {
	pid := strconv.Itoa(os.Getpid())
	file, err := os.Open(filepath.Join("/proc", pid, "stat"))
	if err != nil {
		return 0, err
	}

	buf := acquire()
	defer release(buf)

	if _, err = io.Copy(buf, file); err != nil {
		return 0, err
	}

	fields := strings.Fields(buf.String())
	if len(fields) < 24 {
		return 0, fmt.Errorf("illegal /proc/%s/stat content", pid)
	}

	var rss int64
	if rss, err = strconv.ParseInt(fields[23], 10, 64); err != nil {
		return 0, err
	}

	return rss * int64(os.Getpagesize()), nil
}
