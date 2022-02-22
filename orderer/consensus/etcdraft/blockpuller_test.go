/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package etcdraft_test

import (
	"io/ioutil"
	"testing"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/sw"
	"gitee.com/zhaochuninhefei/fabric-gm/common/crypto/tlsgen"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/pkg/comm"
	"gitee.com/zhaochuninhefei/fabric-gm/orderer/common/cluster"
	"gitee.com/zhaochuninhefei/fabric-gm/orderer/common/cluster/mocks"
	"gitee.com/zhaochuninhefei/fabric-gm/orderer/common/localconfig"
	"gitee.com/zhaochuninhefei/fabric-gm/orderer/consensus"
	"gitee.com/zhaochuninhefei/fabric-gm/orderer/consensus/etcdraft"
	"gitee.com/zhaochuninhefei/fabric-gm/orderer/mocks/common/multichannel"
	"gitee.com/zhaochuninhefei/fabric-gm/protoutil"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/stretchr/testify/assert"
)

func TestEndpointconfigFromFromSupport(t *testing.T) {
	blockBytes, err := ioutil.ReadFile("testdata/mychannel.block")
	assert.NoError(t, err)

	goodConfigBlock := &common.Block{}
	assert.NoError(t, proto.Unmarshal(blockBytes, goodConfigBlock))

	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)

	for _, testCase := range []struct {
		name            string
		height          uint64
		blockAtHeight   *common.Block
		lastConfigBlock *common.Block
		expectedError   string
	}{
		{
			name:          "Block returns nil",
			expectedError: "unable to retrieve block [99]",
			height:        100,
		},
		{
			name:          "Last config block number cannot be retrieved from last block",
			blockAtHeight: &common.Block{},
			expectedError: "failed to retrieve metadata: no metadata in block",
			height:        100,
		},
		{
			name: "Last config block cannot be retrieved",
			blockAtHeight: &common.Block{
				Metadata: &common.BlockMetadata{
					Metadata: [][]byte{{}, protoutil.MarshalOrPanic(&common.Metadata{
						Value: protoutil.MarshalOrPanic(&common.LastConfig{Index: 42}),
					})},
				},
			},
			expectedError: "unable to retrieve last config block [42]",
			height:        100,
		},
		{
			name: "Last config block is retrieved but it is invalid",
			blockAtHeight: &common.Block{
				Metadata: &common.BlockMetadata{
					Metadata: [][]byte{{}, protoutil.MarshalOrPanic(&common.Metadata{
						Value: protoutil.MarshalOrPanic(&common.LastConfig{Index: 42}),
					})},
				},
			},
			lastConfigBlock: &common.Block{},
			expectedError:   "block data is nil",
			height:          100,
		},
		{
			name: "Last config block is retrieved and is valid",
			blockAtHeight: &common.Block{
				Metadata: &common.BlockMetadata{
					Metadata: [][]byte{{}, protoutil.MarshalOrPanic(&common.Metadata{
						Value: protoutil.MarshalOrPanic(&common.LastConfig{Index: 42}),
					})},
				},
			},
			lastConfigBlock: goodConfigBlock,
			height:          100,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cs := &multichannel.ConsenterSupport{
				BlockByIndex: make(map[uint64]*common.Block),
			}
			cs.HeightVal = testCase.height
			cs.BlockByIndex[cs.HeightVal-1] = testCase.blockAtHeight
			cs.BlockByIndex[42] = testCase.lastConfigBlock

			certs, err := etcdraft.EndpointconfigFromSupport(cs, cryptoProvider)
			if testCase.expectedError == "" {
				assert.NotNil(t, certs)
				assert.NoError(t, err)
				return
			}
			assert.EqualError(t, err, testCase.expectedError)
			assert.Nil(t, certs)
		})
	}
}

func TestNewBlockPuller(t *testing.T) {
	ca, err := tlsgen.NewCA()
	assert.NoError(t, err)

	blockBytes, err := ioutil.ReadFile("testdata/mychannel.block")
	assert.NoError(t, err)

	goodConfigBlock := &common.Block{}
	assert.NoError(t, proto.Unmarshal(blockBytes, goodConfigBlock))

	lastBlock := &common.Block{
		Metadata: &common.BlockMetadata{
			Metadata: [][]byte{{}, protoutil.MarshalOrPanic(&common.Metadata{
				Value: protoutil.MarshalOrPanic(&common.LastConfig{Index: 42}),
			})},
		},
	}

	cs := &multichannel.ConsenterSupport{
		HeightVal: 100,
		BlockByIndex: map[uint64]*common.Block{
			42: goodConfigBlock,
			99: lastBlock,
		},
	}

	dialer := &cluster.PredicateDialer{
		Config: comm.ClientConfig{
			SecOpts: comm.SecureOptions{
				Certificate: ca.CertBytes(),
			},
		},
	}

	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)

	bp, err := etcdraft.NewBlockPuller(cs, dialer, localconfig.Cluster{}, cryptoProvider)
	assert.NoError(t, err)
	assert.NotNil(t, bp)

	// From here on, we test failures.
	for _, testCase := range []struct {
		name          string
		expectedError string
		cs            consensus.ConsenterSupport
		dialer        *cluster.PredicateDialer
		certificate   []byte
	}{
		{
			name: "Unable to retrieve block",
			cs: &multichannel.ConsenterSupport{
				HeightVal: 100,
			},
			certificate:   ca.CertBytes(),
			expectedError: "unable to retrieve block [99]",
			dialer:        dialer,
		},
		{
			name:          "Certificate is invalid",
			cs:            cs,
			certificate:   []byte{1, 2, 3},
			expectedError: "client certificate isn't in PEM format: \x01\x02\x03",
			dialer:        dialer,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.dialer.Config.SecOpts.Certificate = testCase.certificate
			bp, err := etcdraft.NewBlockPuller(testCase.cs, testCase.dialer, localconfig.Cluster{}, cryptoProvider)
			assert.Nil(t, bp)
			assert.EqualError(t, err, testCase.expectedError)
		})
	}
}

func TestLedgerBlockPuller(t *testing.T) {
	currHeight := func() uint64 {
		return 1
	}

	genesisBlock := &common.Block{Header: &common.BlockHeader{Number: 0}}
	notGenesisBlock := &common.Block{Header: &common.BlockHeader{Number: 1}}

	blockRetriever := &mocks.BlockRetriever{}
	blockRetriever.On("Block", uint64(0)).Return(genesisBlock)

	puller := &mocks.ChainPuller{}
	puller.On("PullBlock", uint64(1)).Return(notGenesisBlock)

	lbp := &etcdraft.LedgerBlockPuller{
		Height:         currHeight,
		BlockRetriever: blockRetriever,
		BlockPuller:    puller,
	}

	assert.Equal(t, genesisBlock, lbp.PullBlock(0))
	assert.Equal(t, notGenesisBlock, lbp.PullBlock(1))
}