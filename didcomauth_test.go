package didcomauth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gorilla/mux"
)

func TestConfigure(t *testing.T) {

	tests := []struct {
		name    string
		config  Config
		m       *mux.Router
		wantErr bool
	}{
		{
			"nil router",
			Config{},
			nil,
			true,
		},
		{
			"wrong config",
			Config{},
			mux.NewRouter(),
			true,
		},
		{
			"okay config, okay router",
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
			mux.NewRouter(),
			false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr {
				require.Error(t, Configure(tt.config, tt.m))
				return
			}

			require.NoError(t, Configure(tt.config, tt.m))
		})
	}
}
