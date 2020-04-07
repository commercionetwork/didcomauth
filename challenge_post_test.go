package didcomauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	idKeeper "github.com/commercionetwork/commercionetwork/x/id/keeper"

	"github.com/jarcoal/httpmock"

	"github.com/dgrijalva/jwt-go"

	"github.com/stretchr/testify/require"
)

func Test_checkRespCacheValidity(t *testing.T) {
	tests := []struct {
		name    string
		ar      AuthResponse
		c       Challenge
		wantErr bool
	}{
		{
			"different timestamp, same did",
			AuthResponse{
				Challenge: Challenge{
					Timestamp: 1,
					DID:       "d",
				},
			},
			Challenge{
				Timestamp: 0,
				DID:       "d",
			},
			true,
		},
		{
			"equal timestamp, same did",
			AuthResponse{
				Challenge: Challenge{
					Timestamp: 1,
					DID:       "d",
				},
			},
			Challenge{
				Timestamp: 1,
				DID:       "d",
			},
			false,
		},
		{
			"different did, same timestamp",
			AuthResponse{
				Challenge: Challenge{
					Timestamp: 1,
					DID:       "dd",
				},
			},
			Challenge{
				Timestamp: 0,
				DID:       "d",
			},
			true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			e := checkRespCacheValidity(tt.ar, tt.c)
			if tt.wantErr {
				require.Error(t, e)
				return
			}
			require.NoError(t, e)
		})
	}
}

func Test_genJWT(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			"a jwt is created properly",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := genJWT("resource", "did", "key")
			require.NoError(t, err)

			token, tokenError := jwt.Parse(got, func(token *jwt.Token) (interface{}, error) {
				if tt, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || tt.Name != "HS512" {
					return nil, invalidTokenError
				}

				return []byte("key"), nil
			})

			require.NoError(t, tokenError)
			require.True(t, token.Valid)

			claims, ok := token.Claims.(jwt.MapClaims)
			require.True(t, ok)

			require.Equal(t, "resource", claims["resource"])
			require.Equal(t, "did", claims["did"])
		})
	}
}

func Test_router_challengePOSTHandler(t *testing.T) {
	setCosmosConfig()

	okayConfig := Config{
		JWTSecret:    "secret",
		CommercioLCD: "lcd",
	}

	pChallenge := Challenge{
		Challenge: "5_wuVIQm_84TcF7fFy6tM2JNCWVIGXj07qShzJUeHiolREzeLmgnQGNNykxh-v_2-_3zBFDGuvcWmo-tNQZ2EIue_b-evb7biEhrF0rzf15MqBel4RR53EQ4rag6aYLjCI5XlMaWl3IppBOwusXt902Rj14KlsKWGRKt5PIS2lS_OWsz0ZAjcgAFL-XJr2Frrgieg8RLCPTTlq_Og1HJyQ_Pdzyizc7WtG-W8HOd7paUHiVZYnI9gexICFqq-wId-bCC3gfegQbT1oL8klKKIxPa4OED-YTWfSj0-h-qzA_LVax_PIu3afjAXC7ygEHxf3rTuaxCR8IlTORApLCQmwpJthJlwnLvovcf7GKhRX4qPR4bth6MY8l6hr8vQaWoFDMftol64H7pf9KMsyLHzIHjj3qyFCxm530_27Scg0aJ8r40Qmo9qTDH-vNQwdM7hYUwYqTnP664eZ3jYqQRCrjj2J467MBK6j0CfXqhF5QBbWiksLQvEdv8MBdZhgxr_T7WFhPrrOQakk_B3ma1gt1RqRiY0n5GKxRHzCNNR8ILu_BsomeHKdEJ3jDc2XvMk8fm3vbMVClD8c5LpGlx5cMyl6My61-Nz5ZosquUkEoQNRa7CXG5EMcebFz_WRiG9ho5Tt14CaaFoOmT3zuQZMjrw2q9k7lsSDWXZQiZQuyluxGe_X6PPKYGFq_oeHnDzk5jPM9i3ytog7KRhbjW7JG7pWrG7RZevYK2BewjfCk8He5W0xF8yLMZ47NRTp8UnLbNnK3tMZp7zC2bRYSONkE6iPjCIXHnXWjVeeeo8CbawQxp0LauMk8Q_bD9HqNE0Y7ZSvkKFxgBvHLLJvFE7uFfCYpN2-MG9n2ke5n9uOIEnLHTpPX-54zfuq186G_HKATEvL6PL4sN-TO6ODs397Cs2g0FuNKSd3WnxvtsRW0pfw-S1X3J9lU7-rxPyFNDFtG7yW4wyxP7PTa3FXAfYpBQ0uP2TZBLMsAd5H0xRxXVQBnJUsOZ4P8saXVtAS3dHnAu02YEUYiqx_Yn_JFhiVQhL0qn56X9EhStax0VJ4WpoPnJQoDezX2pe_NtICXPnr95b93Mp_S-oLmdsI0KMjMfc9wF7qOAZ8LhL8yMsk8mOLgay4LPEhQVoP5UE8C3ylCwZ35MGc1Rg2Hf45NWliH1fejXlXGBG_ohSsT8oR-KM62PMMmOqeu8fAv7P7ESiXfrU-4MoLH6_kSTVbXIaoABWwx2V6jZEnxvl3Wv-gwWSZCuBcX69DWUswbQkobkVU6U3cbxagS46XsFpUSRV9A-bpFxOceJrOGO02HPlhptJ4w0wEVzS_tWFa7xDrTMc1O1V6n4d7vi8uRa_yMQkw==",
		Timestamp: 1586256784,
		DID:       "did:com:15jv74vsdk23pvvf2a8arex339505mgjytz98xc",
	}

	did := "did:com:15jv74vsdk23pvvf2a8arex339505mgjytz98xc"

	headers := map[string]string{
		DIDHeader:      "did:com:15jv74vsdk23pvvf2a8arex339505mgjytz98xc",
		ResourceHeader: "/resource",
	}

	okayJWT := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjMyNTExOTQwMTM5LCJyZXNvdXJjZSI6Ii9wYXRoIiwiZGlkIjoiZGlkOmNvbToxMnAyNHN0OWFzZjM5NGp2MDRlOHN4cmw5YzM4NGpqcXdlanYwZ2YifQ.QQUAWG0BmQpPiqusnxPKMay0Apj3nbKmbSdi_Ti9JlTd48lI-1gynhMKm2aLhjwZuf4GK_JddjVbyyFdn8CO-g"
	_ = okayJWT

	okayDidDocument := testDidDocument()

	tests := []struct {
		name               string
		responder          httpmock.Responder
		config             Config
		cpError            bool
		authResponse       AuthResponse
		expectedStatus     int
		expectedResponse   string
		precachedChallenge Challenge
	}{
		{
			"no challenge in cache",
			nil,
			okayConfig,
			true,
			AuthResponse{},
			http.StatusBadRequest,
			"challenge not found",
			Challenge{},
		},
		{
			"ddo resolution fails",
			httpmock.NewStringResponder(http.StatusNotFound, "not found"),
			okayConfig,
			false,
			AuthResponse{},
			http.StatusBadRequest,
			"ddo for " + did + " not found",
			pChallenge,
		},
		{
			"ddo okay, authresponse empty",
			httpmock.NewJsonResponderOrPanic(http.StatusOK, ddoResolveResponse{
				Result: idKeeper.ResolveIdentityResponse{
					DidDocument: &okayDidDocument,
				}}),
			okayConfig,
			false,
			AuthResponse{},
			http.StatusBadRequest,
			"challenge field empty",
			pChallenge,
		},
		{
			"ddo okay, authresponse invalid",
			httpmock.NewJsonResponderOrPanic(http.StatusOK, ddoResolveResponse{
				Result: idKeeper.ResolveIdentityResponse{
					DidDocument: &okayDidDocument,
				}}),
			okayConfig,
			false,
			AuthResponse{
				Challenge: Challenge{
					Challenge: "c",
					Timestamp: 0,
					DID:       "d",
				},
				Response: "r",
			},
			http.StatusBadRequest,
			"timestamp invalid",
			pChallenge,
		},
		{
			"ddo okay, challenge and authchallenge are not equal",
			httpmock.NewJsonResponderOrPanic(http.StatusOK, ddoResolveResponse{
				Result: idKeeper.ResolveIdentityResponse{
					DidDocument: &okayDidDocument,
				}}),
			okayConfig,
			false,
			AuthResponse{
				Challenge: Challenge{
					Challenge: pChallenge.Challenge,
					Timestamp: pChallenge.Timestamp + 1,
					DID:       pChallenge.DID,
				},
				Response: "r",
			},
			http.StatusForbidden,
			"response payload invalid",
			pChallenge,
		},
		{
			"ddo okay, response is not base64",
			httpmock.NewJsonResponderOrPanic(http.StatusOK, ddoResolveResponse{
				Result: idKeeper.ResolveIdentityResponse{
					DidDocument: &okayDidDocument,
				}}),
			okayConfig,
			false,
			AuthResponse{
				Challenge: pChallenge,
				Response:  "k",
			},
			http.StatusBadRequest,
			"response format invalid",
			pChallenge,
		},
		{
			"ddo okay, response is base64 but it's not a valid signature",
			httpmock.NewJsonResponderOrPanic(http.StatusOK, ddoResolveResponse{
				Result: idKeeper.ResolveIdentityResponse{
					DidDocument: &okayDidDocument,
				}}),
			okayConfig,
			false,
			AuthResponse{
				Challenge: pChallenge,
				Response:  "YmVsbWVtZQ==",
			},
			http.StatusForbidden,
			"response verification failed",
			pChallenge,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()

			httpmock.RegisterResponder(http.MethodGet, ddoURL(tt.config.CommercioLCD, did), tt.responder)

			r := &router{
				config: tt.config,
				cp:     newCTest(tt.cpError),
			}

			if tt.precachedChallenge != (Challenge{}) {
				_ = r.cp.Set(tt.precachedChallenge)
			}

			arb, err := json.Marshal(tt.authResponse)
			require.NoError(t, err)
			sr := bytes.NewReader(arb)

			req, err := http.NewRequest("POST", "/challenge", sr)
			if err != nil {
				t.Fatal(err)
			}

			for header, value := range headers {
				req.Header.Set(header, value)
			}

			rr := httptest.NewRecorder()

			r.challengePOSTHandler(rr, req)

			require.Equal(t, tt.expectedStatus, rr.Code)
			require.Contains(t, rr.Body.String(), tt.expectedResponse)
		})
	}
}
