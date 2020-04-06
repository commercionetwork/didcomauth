package didcomauth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthResponse_ResponseBytes(t *testing.T) {
	tests := []struct {
		name    string
		ar      AuthResponse
		want    []byte
		wantErr bool
	}{
		{
			"responsebytes returns base64 bytes of ar response field",
			AuthResponse{
				Response: "dGVzdA==",
			},
			[]byte("test"),
			false,
		},
		{
			"bogus data, not base64",
			AuthResponse{
				Response: "randomdata",
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.ar.ResponseBytes()
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, data)
		})
	}
}

func TestAuthResponse_Validate(t *testing.T) {
	tests := []struct {
		name    string
		ar      AuthResponse
		wantErr bool
	}{
		{
			"missing challenge field",
			AuthResponse{
				Challenge: Challenge{},
				Response:  "",
			},
			true,
		},
		{
			"missing response field",
			AuthResponse{
				Challenge: Challenge{
					Challenge: "c",
					Timestamp: 0,
					DID:       "",
				},
				Response: "",
			},
			true,
		},
		{
			"missing did field",
			AuthResponse{
				Challenge: Challenge{
					Challenge: "c",
					Timestamp: 0,
					DID:       "",
				},
				Response: "r",
			},
			true,
		},
		{
			"missing timestamp field",
			AuthResponse{
				Challenge: Challenge{
					Challenge: "c",
					Timestamp: 0,
					DID:       "d",
				},
				Response: "r",
			},
			true,
		},
		{
			"no fields missing",
			AuthResponse{
				Challenge: Challenge{
					Challenge: "c",
					Timestamp: 1,
					DID:       "d",
				},
				Response: "r",
			},
			false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr {
				require.Error(t, tt.ar.Validate())
				return
			}

			require.NoError(t, tt.ar.Validate())
		})
	}
}

func TestChallenge_MarshalBinary(t *testing.T) {
	tests := []struct {
		name     string
		c        Challenge
		wantData []byte
	}{
		{
			"marshalbinary returns json binary of c",
			Challenge{
				Challenge: "c",
				Timestamp: 1,
				DID:       "d",
			},
			[]byte(`{"challenge":"c","timestamp":1,"did":"d"}`),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			data, _ := tt.c.MarshalBinary()
			require.Equal(t, tt.wantData, data)
		})
	}
}

func TestChallenge_SignaturePayload(t *testing.T) {
	tests := []struct {
		name     string
		c        Challenge
		wantData []byte
	}{
		{
			"marshalbinary returns json binary of c",
			Challenge{
				Challenge: "c",
				Timestamp: 1,
				DID:       "d",
			},
			[]byte("c1d"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			data := tt.c.SignaturePayload()
			require.Equal(t, tt.wantData, data)
		})
	}
}
