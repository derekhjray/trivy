package daemon

import (
	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestParseHealthConfig(t *testing.T) {
	tests := []struct {
		config string
		expect *container.HealthConfig
	}{
		{
			config: `HEALTHCHECK &{["CMD-SHELL" "/usr/bin/healthcheck -l"] "20s" "30s" "5s" '\x03'}`,
			expect: &container.HealthConfig{
				Test:        []string{"CMD /usr/bin/healthcheck -l"},
				Interval:    20 * time.Second,
				Timeout:     30 * time.Second,
				StartPeriod: 5 * time.Second,
				Retries:     3,
			},
		},
		{
			config: `HEALTHCHECK &{["CMD-SHELL" "[/usr/bin/healthcheck -l]"] "20s" "30s" "5s" '\x03'}`,
			expect: &container.HealthConfig{
				Test:        []string{"CMD /usr/bin/healthcheck -l"},
				Interval:    20 * time.Second,
				Timeout:     30 * time.Second,
				StartPeriod: 5 * time.Second,
				Retries:     3,
			},
		},
		{
			config: `HEALTHCHECK &{["CMD-SHELL" "[\"/usr/bin/healthcheck\" \"-l\"] CMD test"] "20s" "30s" "5s" '\x03'}`,
			expect: &container.HealthConfig{
				Test:        []string{"CMD /usr/bin/healthcheck -l", "CMD test"},
				Interval:    20 * time.Second,
				Timeout:     30 * time.Second,
				StartPeriod: 5 * time.Second,
				Retries:     3,
			},
		},
		{
			config: `HEALTHCHECK \u0026{[\"CMD\" \"/usr/bin/healthcheck\"] \"30s\" \"30s\" \"5s\" \"0s\" '\\x03'}`,
			expect: &container.HealthConfig{
				Test:        []string{"CMD /usr/bin/healthcheck"},
				Interval:    30 * time.Second,
				Timeout:     30 * time.Second,
				StartPeriod: 5 * time.Second,
				Retries:     3,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.config, func(t *testing.T) {
			config := parseHealthConfig(test.config)
			assert.NotNil(t, config)
			assert.Equal(t, test.expect, config)
		})
	}
}
