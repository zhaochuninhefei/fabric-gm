/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/sw"
	"gitee.com/zhaochuninhefei/fabric-gm/common/util"
	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/x509"
	"github.com/stretchr/testify/assert"
)

func TestSigner(t *testing.T) {
	// TODO: 需要将testdata/signer下的相关文件替换为sm2相关文件
	conf := Config{
		MSPID:        "SampleOrg",
		IdentityPath: filepath.Join("testdata", "signer", "cert.pem"),
		KeyPath:      filepath.Join("testdata", "signer", "8150cb2d09628ccc89727611ebb736189f6482747eff9b8aaaa27e9a382d2e93_sk"),
	}

	signer, err := NewSigner(conf)
	assert.NoError(t, err)

	msg := []byte("foo")
	sig, err := signer.Sign(msg)
	assert.NoError(t, err)

	// r, s, err := utils.UnmarshalECDSASignature(sig)
	r, s, err := sw.UnmarshalSM2Signature(sig)
	assert.NoError(t, err)
	// Verify -> Sm2Verify ComputeSHA256 -> ComputeSM3
	sm2.Sm2Verify(&signer.key.PublicKey, util.ComputeSM3(msg), nil, r, s)
}

func TestSignerDifferentFormats(t *testing.T) {
	key := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOwCtOQIkowasuWoDQpXHgC547VHq+aBFaSyPOoV8mnGoAoGCCqGSM49
AwEHoUQDQgAEEsrroAkPez9reWvJukufUqyfouJjakrKuhNBYuclkldqsLZ/TO+w
ZsQXrlIqlmNalfYPX+NDDELqlpXQBeEqnA==
-----END EC PRIVATE KEY-----`

	pemBlock, _ := pem.Decode([]byte(key))
	assert.NotNil(t, pemBlock)

	ecPK, err := x509.ParseSm2PrivateKey(pemBlock.Bytes)
	assert.NoError(t, err)

	ec1, err := x509.MarshalECPrivateKey(ecPK)
	assert.NoError(t, err)

	pkcs8, err := x509.MarshalSm2PrivateKey(ecPK, nil)
	assert.NoError(t, err)

	for _, testCase := range []struct {
		description string
		keyBytes    []byte
	}{
		{
			description: "EC1",
			keyBytes:    pem.EncodeToMemory(&pem.Block{Type: "EC Private Key", Bytes: ec1}),
		},
		{
			description: "PKCS8",
			keyBytes:    pem.EncodeToMemory(&pem.Block{Type: "Private Key", Bytes: pkcs8}),
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			tmpFile, err := ioutil.TempFile("", "key")
			assert.NoError(t, err)

			defer os.Remove(tmpFile.Name())

			err = ioutil.WriteFile(tmpFile.Name(), []byte(testCase.keyBytes), 0600)
			assert.NoError(t, err)

			signer, err := NewSigner(Config{
				MSPID:        "MSPID",
				IdentityPath: filepath.Join("testdata", "signer", "cert.pem"),
				KeyPath:      tmpFile.Name(),
			})

			assert.NoError(t, err)
			assert.NotNil(t, signer)
		})
	}
}

func TestSignerBadConfig(t *testing.T) {
	conf := Config{
		MSPID:        "SampleOrg",
		IdentityPath: filepath.Join("testdata", "signer", "non_existent_cert"),
	}

	signer, err := NewSigner(conf)
	assert.EqualError(t, err, "open testdata/signer/non_existent_cert: no such file or directory")
	assert.Nil(t, signer)

	conf = Config{
		MSPID:        "SampleOrg",
		IdentityPath: filepath.Join("testdata", "signer", "cert.pem"),
		KeyPath:      filepath.Join("testdata", "signer", "non_existent_cert"),
	}

	signer, err = NewSigner(conf)
	assert.EqualError(t, err, "open testdata/signer/non_existent_cert: no such file or directory")
	assert.Nil(t, signer)

	conf = Config{
		MSPID:        "SampleOrg",
		IdentityPath: filepath.Join("testdata", "signer", "cert.pem"),
		KeyPath:      filepath.Join("testdata", "signer", "broken_private_key"),
	}

	signer, err = NewSigner(conf)
	assert.EqualError(t, err, "failed to decode PEM block from testdata/signer/broken_private_key")
	assert.Nil(t, signer)

	conf = Config{
		MSPID:        "SampleOrg",
		IdentityPath: filepath.Join("testdata", "signer", "cert.pem"),
		KeyPath:      filepath.Join("testdata", "signer", "empty_private_key"),
	}

	signer, err = NewSigner(conf)
	assert.EqualError(t, err, "failed to parse private key: x509: failed to parse EC private key: asn1: syntax error: sequence truncated")
	assert.Nil(t, signer)
}
