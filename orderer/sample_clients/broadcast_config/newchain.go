// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"gitee.com/zhaochuninhefei/fabric-gm/internal/configtxgen/encoder"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/configtxgen/genesisconfig"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/pkg/identity"
	cb "gitee.com/zhaochuninhefei/fabric-protos-go-gm/common"
)

func newChainRequest(
	consensusType,
	creationPolicy,
	newChannelID string,
	signer identity.SignerSerializer,
) *cb.Envelope {
	env, err := encoder.MakeChannelCreationTransaction(
		newChannelID,
		signer,
		genesisconfig.Load(genesisconfig.SampleSingleMSPChannelProfile),
	)
	if err != nil {
		panic(err)
	}
	return env
}
