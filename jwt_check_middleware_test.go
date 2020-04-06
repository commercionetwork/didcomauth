package didcomauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_getBearer(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			"no bearer string",
			"nobearer",
			"",
		},
		{
			"Bearer present but no string",
			"Bearer ",
			"",
		},
		{
			"Bearer string okay",
			"Bearer okay",
			"okay",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, getBearer(tt.input))
		})
	}
}

func Test_checkAuthMiddleware(t *testing.T) {
	r := &router{}

	f := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name string
		f    http.HandlerFunc
	}{
		{
			"function returns an instance of checkAuthMiddleware with the next defined properly",
			f,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			h := r.checkAuthMiddleware(tt.f).(checkAuth)
			require.NotNil(t, h)
			require.NotNil(t, h.next)
		})
	}
}

func Test_checkAuth_ServeHTTP(t *testing.T) {
	setCosmosConfig()

	r := &router{
		config: Config{
			JWTSecret: "secret",
		},
	}

	tests := []struct {
		name           string
		headers        map[string]string
		expectedStatus int
		expectedData   string
		path           string
		nextHandler    http.HandlerFunc
	}{
		{
			"bearer header not present",
			nil,
			http.StatusForbidden,
			"not authorized",
			"/path",
			nil,
		},
		{
			"bearer header present, but token itself isn't",
			map[string]string{
				authHeader: "Bearer ",
			},
			http.StatusForbidden,
			"not authorized",
			"/path",
			nil,
		},
		{
			"bearer header present, but token does not begin with Bearer",
			map[string]string{
				authHeader: "NotBearer ",
			},
			http.StatusForbidden,
			"not authorized",
			"/path",
			nil,
		},
		{
			"bearer with invalid algorithm",
			map[string]string{
				authHeader:     "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjMyNTExOTQwMTM5LCJSZXNvdXJjZSI6Ii9wYXRoIiwiRElEIjoiZGlkOmNvbToxMnAyNHN0OWFzZjM5NGp2MDRlOHN4cmw5YzM4NGpqcXdlanYwZ2YifQ.ElGtOX7hy3yNraElMQihKQ7YZe2KstebRd-M4ZyEBfs",
				DIDHeader:      "did:com:12p24st9asf394jv04e8sxrl9c384jjqwejv0gf",
				ResourceHeader: "/path",
			},
			http.StatusForbidden,
			"invalid token",
			"/path",
			nil,
		},
		{
			"wrong secret",
			map[string]string{
				authHeader:     "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjMyNTExOTQwMTM5LCJSZXNvdXJjZSI6Ii9wYXRoIiwiRElEIjoiZGlkOmNvbToxMnAyNHN0OWFzZjM5NGp2MDRlOHN4cmw5YzM4NGpqcXdlanYwZ2YifQ.ShpUomGNuMyXRMNDrSaCv332VBIWkLdZ1MNjgGrZ6wRav0KZUuQBYlR1taz0M1t0OBGuuda1jYuNwCv22Ya3bw",
				DIDHeader:      "did:com:12p24st9asf394jv04e8sxrl9c384jjqwejv0gf",
				ResourceHeader: "/path",
			},
			http.StatusForbidden,
			"invalid token",
			"/path",
			nil,
		},
		{
			"header did differs from jwt claim did",
			map[string]string{
				authHeader:     "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjMyNTExOTQwMTM5LCJyZXNvdXJjZSI6Ii9wYXRoIiwiZGlkIjoiZGlkOmNvbToxMnAyNHN0OWFzZjM5NGp2MDRlOHN4cmw5YzM4NGpqcXdlanYwZ2YifQ.QQUAWG0BmQpPiqusnxPKMay0Apj3nbKmbSdi_Ti9JlTd48lI-1gynhMKm2aLhjwZuf4GK_JddjVbyyFdn8CO-g",
				DIDHeader:      "did:com:12p24st9asf394jv04e8sxrl9c384jjqwejv0gfNotEqual!",
				ResourceHeader: "/path",
			},
			http.StatusForbidden,
			"invalid token",
			"/path",
			nil,
		},
		{
			"header resource differs from jwt claim resource",
			map[string]string{
				authHeader:     "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjMyNTExOTQwMTM5LCJyZXNvdXJjZSI6Ii9wYXRoIiwiZGlkIjoiZGlkOmNvbToxMnAyNHN0OWFzZjM5NGp2MDRlOHN4cmw5YzM4NGpqcXdlanYwZ2YifQ.QQUAWG0BmQpPiqusnxPKMay0Apj3nbKmbSdi_Ti9JlTd48lI-1gynhMKm2aLhjwZuf4GK_JddjVbyyFdn8CO-g",
				DIDHeader:      "did:com:12p24st9asf394jv04e8sxrl9c384jjqwejv0gf",
				ResourceHeader: "/pathNotEqual!",
			},
			http.StatusForbidden,
			"invalid token",
			"/path",
			nil,
		},
		{
			"jwt okay but resources are different",
			map[string]string{
				authHeader:     "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjMyNTExOTQwMTM5LCJyZXNvdXJjZSI6Ii9wYXRoIiwiZGlkIjoiZGlkOmNvbToxMnAyNHN0OWFzZjM5NGp2MDRlOHN4cmw5YzM4NGpqcXdlanYwZ2YifQ.QQUAWG0BmQpPiqusnxPKMay0Apj3nbKmbSdi_Ti9JlTd48lI-1gynhMKm2aLhjwZuf4GK_JddjVbyyFdn8CO-g",
				DIDHeader:      "did:com:12p24st9asf394jv04e8sxrl9c384jjqwejv0gf",
				ResourceHeader: "/path",
			},
			http.StatusForbidden,
			"",
			"/pathDifferent",
			nil,
		},
		{
			"jwt validation pass",
			map[string]string{
				authHeader:     "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjMyNTExOTQwMTM5LCJyZXNvdXJjZSI6Ii9wYXRoIiwiZGlkIjoiZGlkOmNvbToxMnAyNHN0OWFzZjM5NGp2MDRlOHN4cmw5YzM4NGpqcXdlanYwZ2YifQ.QQUAWG0BmQpPiqusnxPKMay0Apj3nbKmbSdi_Ti9JlTd48lI-1gynhMKm2aLhjwZuf4GK_JddjVbyyFdn8CO-g",
				DIDHeader:      "did:com:12p24st9asf394jv04e8sxrl9c384jjqwejv0gf",
				ResourceHeader: "/path",
			},
			http.StatusOK,
			"",
			"/path",
			func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusOK)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			n := checkAuth{
				next: tt.nextHandler, // we just check that the middleware itself works
				r:    r,
			}

			req, err := http.NewRequest("GET", tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			for header, value := range tt.headers {
				req.Header.Set(header, value)
			}

			rr := httptest.NewRecorder()

			n.ServeHTTP(rr, req)

			require.Equal(t, tt.expectedStatus, rr.Code)
			require.Contains(t, rr.Body.String(), tt.expectedData)
		})
	}
}
