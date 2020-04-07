package didcomauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_getRandomChallenge(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			"generate some random entropy",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			data, err := getRandomChallenge()
			require.NoError(t, err)
			require.NotEmpty(t, data)
		})
	}
}

func Test_router_challengeGETHandler(t *testing.T) {
	// in this test we assume that did header is set, because the
	// middleware checks for it
	setCosmosConfig()

	headers := map[string]string{
		DIDHeader:      "did:com:15jv74vsdk23pvvf2a8arex339505mgjytz98xc",
		ResourceHeader: "/resource",
	}

	tests := []struct {
		name           string
		expectedStatus int
		expectedData   string
		cpError        bool
	}{
		{
			"cache provider does error",
			http.StatusInternalServerError,
			"could not process Challenge",
			true,
		},
		{
			"cache provider tests okay, challenge created",
			http.StatusOK,
			"could not process Challenge",
			false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			r := &router{
				cp: newCTest(tt.cpError),
			}

			req, err := http.NewRequest("GET", "/challenge", nil)
			if err != nil {
				t.Fatal(err)
			}

			for header, value := range headers {
				req.Header.Set(header, value)
			}

			rr := httptest.NewRecorder()

			r.challengeGETHandler(rr, req)

			require.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK {
				var c Challenge
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &c))

				require.NotEmpty(t, c.Challenge)
				require.NotEmpty(t, c.DID)
				require.NotEmpty(t, c.Timestamp)

			} else {
				require.Contains(t, rr.Body.String(), tt.expectedData)
			}
		})
	}
}
