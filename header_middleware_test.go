package didcomauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_checkDID(t *testing.T) {
	setCosmosConfig()

	tests := []struct {
		name    string
		did     string
		wantErr bool
	}{
		{
			"a good did",
			"did:com:15jv74vsdk23pvvf2a8arex339505mgjytz98xc",
			false,
		},
		{
			"wrong did",
			"wrong",
			true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr {
				require.Error(t, checkDID(tt.did))
				return
			}

			require.NoError(t, checkDID(tt.did))
		})
	}
}

func Test_neededHeaders_ServeHTTP(t *testing.T) {
	setCosmosConfig()

	tests := []struct {
		name           string
		headers        map[string]string
		expectedStatus int
		expectedData   string
		nextHandler    http.HandlerFunc
	}{
		{
			"no required headers",
			nil,
			http.StatusBadRequest,
			"X-DID header not defined", // the first thing we check is the DID, so we expect a did-related error first
			nil,
		},
		{
			"just X-DID defined",
			map[string]string{
				DIDHeader: "did",
			},
			http.StatusBadRequest,
			"X-Resource header not defined",
			nil,
		},
		{
			"both headers defined, bad DID",
			map[string]string{
				DIDHeader:      "did",
				ResourceHeader: "/resource",
			},
			http.StatusBadRequest,
			"invalid DID",
			nil,
		},
		{
			"both headers defined, okay did DID",
			map[string]string{
				DIDHeader:      "did:com:15jv74vsdk23pvvf2a8arex339505mgjytz98xc",
				ResourceHeader: "/resource",
			},
			http.StatusOK,
			"",
			func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusOK)
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			n := neededHeaders{
				next: tt.nextHandler, // we just check that the middleware itself works
			}

			req, err := http.NewRequest("GET", "/needed-headers", nil)
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

func Test_neededHeadersMiddleware(t *testing.T) {
	f := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name string
		f    http.HandlerFunc
	}{
		{
			"function returns an instance of neededHeaders with the next defined properly",
			f,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			h := neededHeadersMiddleware(tt.f).(neededHeaders)
			require.NotNil(t, h)
			require.NotNil(t, h.next)
		})
	}
}
