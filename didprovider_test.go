package didcomauth

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"

	idKeeper "github.com/commercionetwork/commercionetwork/x/id/keeper"

	"github.com/stretchr/testify/require"

	"github.com/commercionetwork/commercionetwork/x/id/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func testDidDocument() types.DidDocument {
	setCosmosConfig()
	var testZone, _ = time.LoadLocation("UTC")
	var testTime = time.Date(2016, 2, 8, 16, 2, 20, 0, testZone)
	var testOwnerAddress, _ = sdk.AccAddressFromBech32("did:com:12p24st9asf394jv04e8sxrl9c384jjqwejv0gf")

	return types.DidDocument{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      testOwnerAddress,
		Proof: types.Proof{
			Type:               "EcdsaSecp256k1VerificationKey2019",
			Created:            testTime,
			ProofPurpose:       "authentication",
			Controller:         testOwnerAddress.String(),
			SignatureValue:     "4T2jhs4C0k7p649tdzQAOLqJ0GJsiFDP/NnsSkFpoXAxcgn6h/EgvOpHxW7FMNQ9RDgQbcE6FWP6I2UsNv1qXQ==",
			VerificationMethod: "did:com:pub1addwnpepqwzc44ggn40xpwkfhcje9y7wdz6sunuv2uydxmqjrvcwff6npp2exy5dn6c",
		},
		PubKeys: types.PubKeys{
			types.PubKey{
				ID:         fmt.Sprintf("%s#keys-1", testOwnerAddress),
				Type:       "RsaVerificationKey2018",
				Controller: testOwnerAddress,
				PublicKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqOoLR843vgkFGudQsjch
2K85QJ4Hh7l2jjrMesQFDWVcW1xr//eieGzxDogWx7tMOtQ0hw77NAURhldek1Bh
Co06790YHAE97JqgRQ+IR9Dl3GaGVQ2WcnknO4B1cvTRJmdsqrN1Bs4Qfd+jjKIM
V1tz8zU9NmdR+DvGkAYYxoIx74YaTAxH+GCArfWMG1tRJPI9MELZbOWd9xkKlPic
bLp8coZh9NgLajMDWKXpuHQ8cdJSxQ/ekZaTuEy7qbjbGBMVzbjhPjcxffQmGV1W
gNY1BGplZz9mbBmH7siKnKIVZ5Bp55uLfEw+u2yOVx/0yKUdsmZoe4jhevCSq3aw
GwIDAQAB
-----END PUBLIC KEY-----`,
			},
			types.PubKey{
				ID:         fmt.Sprintf("%s#keys-2", testOwnerAddress),
				Type:       "RsaSignatureKey2018",
				Controller: testOwnerAddress,
				PublicKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+Juw6xqYchTNFYUznmoB
CzKfQG75v2Pv1Db1Z5EJgP6i0yRsBG1VqIOY4icRnyhDDVFi1omQjjUuCRxWGjsc
B1UkSnybm0WC+g82HL3mUzbZja27NFJPuNaMaUlNbe0daOG88FS67jq5J2LsZH/V
cGZBX5bbtCe0Niq39mQdJxdHq3D5ROMA73qeYvLkmXS6Dvs0w0fHsy+DwJtdOnOj
xt4F5hIEXGP53qz2tBjCRL6HiMP/cLSwAd7oc67abgQxfnf9qldyd3X0IABpti1L
irJNugfN6HuxHDm6dlXVReOhHRbkEcWedv82Ji5d/sDZ+WT+yWILOq03EJo/LXJ1
SQIDAQAB
-----END PUBLIC KEY-----`,
			},
		},
	}
}

func Test_ddoResolveResponse_SigningPubKey(t *testing.T) {

	okayDDO := testDidDocument()

	wrongDDO := testDidDocument()
	wrongDDO.PubKeys[1] = types.PubKey{
		ID:         "did:com:12p24st9asf394jv04e8sxrl9c384jjqwejv0gf#keys-2",
		Type:       "",
		Controller: nil,
		PublicKey:  "",
	}

	tests := []struct {
		name    string
		drr     ddoResolveResponse
		wantErr bool
	}{
		{
			"a good diddocument",
			ddoResolveResponse{Result: idKeeper.ResolveIdentityResponse{
				DidDocument: &okayDDO,
			}},
			false,
		},
		{
			"diddocument without a key",
			ddoResolveResponse{Result: idKeeper.ResolveIdentityResponse{
				DidDocument: &types.DidDocument{},
			}},
			true,
		},
		{
			"diddocument with wrong key",
			ddoResolveResponse{Result: idKeeper.ResolveIdentityResponse{
				DidDocument: &wrongDDO,
			}},
			true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			k, e := tt.drr.SigningPubKey()

			if tt.wantErr {
				require.Nil(t, k)
				require.Error(t, e)
				return
			}

			require.NotNil(t, k)
			require.NoError(t, e)
		})
	}
}

func Test_ddoURL(t *testing.T) {

	tests := []struct {
		name string
		lcd  string
		did  string
		want string
	}{
		{
			"expected value is returned correctly",
			"http://test",
			"did",
			"http://test/identities/did",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ddoURL(tt.lcd, tt.did))
		})
	}
}

func Test_resolveDDO(t *testing.T) {
	lcd := "lcd"
	did := "did"

	mockUrl := ddoURL(lcd, did)

	okayDidDocument := testDidDocument()

	tests := []struct {
		name      string
		responder httpmock.Responder
		wantErr   bool
	}{
		{
			"http call goes error",
			httpmock.NewErrorResponder(errors.New("error!")),
			true,
		},
		{
			"lcd returns non-200",
			httpmock.NewStringResponder(http.StatusInternalServerError, "internal server error"),
			true,
		},
		{
			"ddo for did not found",
			httpmock.NewStringResponder(http.StatusNotFound, "not found"),
			true,
		},
		{
			"wrong json",
			httpmock.NewStringResponder(http.StatusOK, "this is not json"),
			true,
		},
		{
			"okay response",
			httpmock.NewJsonResponderOrPanic(http.StatusOK, ddoResolveResponse{
				Result: idKeeper.ResolveIdentityResponse{
					DidDocument: &okayDidDocument,
				}}),
			false,
		},
		{
			"okay response but diddocument is nil",
			httpmock.NewJsonResponderOrPanic(http.StatusOK, ddoResolveResponse{
				Result: idKeeper.ResolveIdentityResponse{
					DidDocument: nil,
				}}),
			true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			httpmock.Activate()
			defer httpmock.DeactivateAndReset()

			httpmock.RegisterResponder(http.MethodGet, mockUrl, tt.responder)

			ddo, err := resolveDDO(lcd, did)

			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, ddo.Result.DidDocument)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, ddo.Result.DidDocument)
		})
	}
}
