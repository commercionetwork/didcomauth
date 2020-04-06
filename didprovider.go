package didcomauth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	idKeeper "github.com/commercionetwork/commercionetwork/x/id/keeper"
)

const (
	comDDOResolutionPath = "%s/identities/%s"
)

type ddoResolveResponse struct {
	Result idKeeper.ResolveIdentityResponse `json:"result"`
}

func (drr ddoResolveResponse) SigningPubKey() (*rsa.PublicKey, error) {
	rawKeyStr := ""
	for _, k := range drr.Result.DidDocument.PubKeys {
		if strings.HasSuffix(k.ID, "#keys-2") {
			rawKeyStr = k.PublicKey
		}
	}

	if rawKeyStr == "" {
		return nil, errors.New("DDO doesn't have a verification key")
	}

	block, _ := pem.Decode([]byte(rawKeyStr))

	rawKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	key, ok := rawKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("selected key is not an rsa public key")
	}

	return key, nil
}

func ddoURL(lcd string, did string) string {
	return fmt.Sprintf(comDDOResolutionPath, lcd, did)
}

// resolveDDO resolves the DDO for did by querying lcd.
func resolveDDO(lcd string, did string) (ddoResolveResponse, error) {
	u := ddoURL(lcd, did)

	data, err := http.Get(u)
	if err != nil {
		return ddoResolveResponse{}, fmt.Errorf("could not resolve DDO, %w", err)
	}

	if data.StatusCode == http.StatusNotFound {
		return ddoResolveResponse{}, fmt.Errorf("ddo for %s not found", did)
	}

	if data.StatusCode != http.StatusOK {
		return ddoResolveResponse{}, fmt.Errorf("LCD node responded with status %d", data.StatusCode)
	}

	var drr ddoResolveResponse
	jdec := json.NewDecoder(data.Body)
	err = jdec.Decode(&drr)
	if err != nil {
		return ddoResolveResponse{}, fmt.Errorf("could not unmarshal DDO, %w", err)
	}

	if drr.Result.DidDocument == nil {
		return ddoResolveResponse{}, errors.New("ddo resolution okay but document is empty")
	}

	_ = data.Body.Close()

	return drr, nil
}
