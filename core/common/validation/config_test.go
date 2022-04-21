/*
Copyright IBM Corp. 2016 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package validation

import (
	"testing"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/sw"
	"gitee.com/zhaochuninhefei/fabric-gm/core/config/configtest"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/configtxgen/encoder"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/configtxgen/genesisconfig"
	"gitee.com/zhaochuninhefei/fabric-gm/protoutil"
	cb "gitee.com/zhaochuninhefei/fabric-protos-go-gm/common"
	"gitee.com/zhaochuninhefei/fabric-protos-go-gm/peer"
	"github.com/stretchr/testify/assert"
)

func TestValidateConfigTx(t *testing.T) {
	channelID := "testchannelid"
	profile := genesisconfig.Load(genesisconfig.SampleSingleMSPChannelProfile, configtest.GetDevConfigDir())
	chCrtEnv, err := encoder.MakeChannelCreationTransaction(genesisconfig.SampleConsortiumName, nil, profile)
	if err != nil {
		t.Fatalf("MakeChannelCreationTransaction failed, err %s", err)
		return
	}

	updateResult := &cb.Envelope{
		Payload: protoutil.MarshalOrPanic(&cb.Payload{Header: &cb.Header{
			ChannelHeader: protoutil.MarshalOrPanic(&cb.ChannelHeader{
				Type:      int32(cb.HeaderType_CONFIG),
				ChannelId: channelID,
			}),
			SignatureHeader: protoutil.MarshalOrPanic(&cb.SignatureHeader{
				Creator: signerSerialized,
				Nonce:   protoutil.CreateNonceOrPanic(),
			}),
		},
			Data: protoutil.MarshalOrPanic(&cb.ConfigEnvelope{
				LastUpdate: chCrtEnv,
			}),
		}),
	}
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)
	updateResult.Signature, _ = signer.Sign(updateResult.Payload)
	_, txResult := ValidateTransaction(updateResult, cryptoProvider)
	if txResult != peer.TxValidationCode_VALID {
		t.Fatalf("ValidateTransaction failed, err %s", err)
		return
	}
}
