package crypto

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func GetFile(path string) string {
	data, err := os.ReadFile(path)

	if err != nil {
		log.Fatalf("Cannot read file %s: %s", path, err)
	}

	return string(data)
}

func GetFixture(file string) string {
	return GetFile(fmt.Sprintf("./fixtures/%s.json", file))
}

func GetIdentityFixture() TestingIdentityFixture {
	data := GetFixture("identity")

	var fixture TestingIdentityFixture
	_ = json.Unmarshal([]byte(data), &fixture)

	return fixture
}

func GetMessageFixture() TestingMessageFixture {
	data := GetFixture("message")

	var fixture TestingMessageFixture
	_ = json.Unmarshal([]byte(data), &fixture)

	return fixture
}

func GetBLSValidatorFixture() BLSValidatorFixture {
	data := GetFixture("bls_validator")

	var fixture BLSValidatorFixture
	_ = json.Unmarshal([]byte(data), &fixture)

	return fixture
}

func GetBLSKeysFixture() []BLSKeyFixture {
	data := GetFixture("bls_keys")

	var fixtures []BLSKeyFixture
	_ = json.Unmarshal([]byte(data), &fixtures)

	return fixtures
}

func GetBLSMultiLangKeysFixture() map[string][]BLSMultiLangKeyFixture {
	data := GetFixture("bls_multi_lang")

	var fixtures map[string][]BLSMultiLangKeyFixture
	_ = json.Unmarshal([]byte(data), &fixtures)

	return fixtures
}

func GetTransactionFixture(name string) TestingTransactionFixture {
	data := GetFile(fmt.Sprintf("./fixtures/transactions/%s.json", name))

	var fixture TestingTransactionFixture
	_ = json.Unmarshal([]byte(data), &fixture)

	return fixture
}

type TestingIdentityFixture struct {
	Data struct {
		PrivateKey          string `json:"privateKey,omitempty"`
		PublicKey           string `json:"publicKey,omitempty"`
		Address             string `json:"address,omitempty"`
		WIF                 string `json:"wif,omitempty"`
		ValidatorPublicKey  string `json:"validatorPublicKey,omitempty"`
		ValidatorPrivateKey string `json:"validatorPrivateKey,omitempty"`
	} `json:"data,omitempty"`
	Passphrase       string `json:"passphrase,omitempty"`
	SecondPassphrase string `json:"secondPassphrase,omitempty"`
}

type TestingMessageFixture struct {
	Data struct {
		PublicKey string `json:"publickey,omitempty"`
		Signature string `json:"signature,omitempty"`
		Message   string `json:"message,omitempty"`
	} `json:"data,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}
type BLSValidatorFixture struct {
	BLSPublicKey  string `json:"bls_public_key"`
	BLSPrivateKey string `json:"bls_private_key"`
	Passphrase    string `json:"passphrase"`
}

type BLSKeyFixture struct {
	BLSPublicKey      string `json:"bls_public_key"`
	BLSPrivateKey     string `json:"bls_private_key"`
	ProofOfPossession string `json:"proof_of_possession"`
	Passphrase        string `json:"passphrase"`
}

type TestingTransactionFixture struct {
	Data struct {
		Nonce           string `json:"nonce"`
		GasPrice        string `json:"gasPrice"`
		GasLimit        string `json:"gasLimit"`
		To              string `json:"to"`
		Value           string `json:"value"`
		Data            string `json:"data"`
		Network         int    `json:"network"`
		V               int    `json:"v"`
		R               string `json:"r"`
		S               string `json:"s"`
		SenderPublicKey string `json:"senderPublicKey"`
		From            string `json:"from"`
		Hash            string `json:"hash"`
	} `json:"data"`
	Serialized string `json:"serialized"`
}

type BLSMultiLangKeyFixture struct {
	Mnemonic            string `json:"mnemonic"`
	ValidatorPrivateKey string `json:"validatorPrivateKey"`
	ValidatorPublicKey  string `json:"validatorPublicKey"`
	ValidatorPop        string `json:"validatorPop"`
}
