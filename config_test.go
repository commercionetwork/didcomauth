package didcomauth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			"no jwt secret",
			Config{
				ProtectedPaths: []ProtectedMapping{
					{
						Methods: []string{http.MethodGet},
						Path:    "/get",
						Handler: nil,
					},
				},
			},
			true,
		},
		{
			"no protected paths specified",
			Config{JWTSecret: "secret"},
			true,
		},
		{
			"missing cache type",
			Config{
				JWTSecret: "secret",
				ProtectedPaths: []ProtectedMapping{
					{
						Methods: []string{http.MethodGet},
						Path:    "/get",
						Handler: nil,
					},
				},
			},
			true,
		},
		{
			"basic fields present",
			Config{
				JWTSecret: "secret",
				ProtectedPaths: []ProtectedMapping{
					{
						Methods: []string{http.MethodGet},
						Path:    "/get",
						Handler: nil,
					},
				},
				CacheType: CacheTypeMemory,
			},
			false,
		},
		{
			"basic fields present with redis",
			Config{
				JWTSecret: "secret",
				ProtectedPaths: []ProtectedMapping{
					{
						Methods: []string{http.MethodGet},
						Path:    "/get",
						Handler: nil,
					},
				},
				CacheType: CacheTypeRedis,
			},
			false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr {
				require.Error(t, tt.config.Validate())
				return
			}

			require.NoError(t, tt.config.Validate())
		})
	}
}
