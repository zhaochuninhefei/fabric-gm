/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msgprocessor

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"gitee.com/zhaochuninhefei/fabric-gm/common/channelconfig"
	"gitee.com/zhaochuninhefei/fabric-gm/orderer/common/msgprocessor/mocks"
	"gitee.com/zhaochuninhefei/fabric-gm/protoutil"
	"gitee.com/zhaochuninhefei/fabric-protos-go-gm/common"
	"gitee.com/zhaochuninhefei/fabric-protos-go-gm/msp"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

//go:generate counterfeiter -o mocks/config_resources.go --fake-name Resources . configResources

type configResources interface {
	channelconfig.Resources
}

//go:generate counterfeiter -o mocks/orderer_config.go --fake-name OrdererConfig . ordererConfig

type ordererConfig interface {
	channelconfig.Orderer
}

//go:generate counterfeiter -o mocks/orderer_capabilities.go --fake-name OrdererCapabilities . ordererCapabilities

type ordererCapabilities interface {
	channelconfig.OrdererCapabilities
}

func createEnvelope(t *testing.T, serializedIdentity []byte) *common.Envelope {
	sHdr := protoutil.MakeSignatureHeader(serializedIdentity, nil)
	hdr := protoutil.MakePayloadHeader(&common.ChannelHeader{}, sHdr)
	payload := &common.Payload{
		Header: hdr,
	}
	payloadBytes, err := proto.Marshal(payload)
	assert.NoError(t, err)
	return &common.Envelope{
		Payload:   payloadBytes,
		Signature: []byte{1, 2, 3},
	}
}

func createX509Identity(t *testing.T, certFileName string) []byte {
	certBytes, err := ioutil.ReadFile(filepath.Join("testdata", certFileName))
	assert.NoError(t, err)
	sId := &msp.SerializedIdentity{
		IdBytes: certBytes,
	}
	idBytes, err := proto.Marshal(sId)
	assert.NoError(t, err)
	return idBytes
}

func createIdemixIdentity(t *testing.T) []byte {
	idemixId := &msp.SerializedIdemixIdentity{
		NymX: []byte{1, 2, 3},
		NymY: []byte{1, 2, 3},
		Ou:   []byte("OU1"),
	}
	idemixBytes, err := proto.Marshal(idemixId)
	assert.NoError(t, err)
	sId := &msp.SerializedIdentity{
		IdBytes: idemixBytes,
	}
	idBytes, err := proto.Marshal(sId)
	assert.NoError(t, err)
	return idBytes
}

func TestExpirationRejectRule(t *testing.T) {
	mockResources := &mocks.Resources{}

	t.Run("NoOrdererConfig", func(t *testing.T) {
		assert.Panics(t, func() {
			NewExpirationRejectRule(mockResources).Apply(&common.Envelope{})
		})
	})

	mockOrderer := &mocks.OrdererConfig{}
	mockResources.OrdererConfigReturns(mockOrderer, true)
	mockCapabilities := &mocks.OrdererCapabilities{}
	mockOrderer.CapabilitiesReturns(mockCapabilities)

	t.Run("BadEnvelope", func(t *testing.T) {
		mockCapabilities.ExpirationCheckReturns(true)
		err := NewExpirationRejectRule(mockResources).Apply(&common.Envelope{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not convert message to signedData")

		mockCapabilities.ExpirationCheckReturns(false)
		err = NewExpirationRejectRule(mockResources).Apply(&common.Envelope{})
		assert.NoError(t, err)
	})

	t.Run("ExpiredX509Identity", func(t *testing.T) {
		env := createEnvelope(t, createX509Identity(t, "expiredCert.pem"))
		mockCapabilities.ExpirationCheckReturns(true)
		err := NewExpirationRejectRule(mockResources).Apply(env)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "broadcast client identity expired")

		mockCapabilities.ExpirationCheckReturns(false)
		err = NewExpirationRejectRule(mockResources).Apply(env)
		assert.NoError(t, err)
	})
	t.Run("IdemixIdentity", func(t *testing.T) {
		env := createEnvelope(t, createIdemixIdentity(t))
		mockCapabilities.ExpirationCheckReturns(true)
		assert.Nil(t, NewExpirationRejectRule(mockResources).Apply(env))
		mockCapabilities.ExpirationCheckReturns(false)
		assert.Nil(t, NewExpirationRejectRule(mockResources).Apply(env))
	})
	t.Run("NoneExpiredX509Identity", func(t *testing.T) {
		env := createEnvelope(t, createX509Identity(t, "cert.pem"))
		mockCapabilities.ExpirationCheckReturns(true)
		assert.Nil(t, NewExpirationRejectRule(mockResources).Apply(env))
		mockCapabilities.ExpirationCheckReturns(false)
		assert.Nil(t, NewExpirationRejectRule(mockResources).Apply(env))
	})
}
