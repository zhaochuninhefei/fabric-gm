/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package test

import (
	"gitee.com/zhaochuninhefei/fabric-gm/common/channelconfig"
	"gitee.com/zhaochuninhefei/fabric-gm/common/flogging"
	"gitee.com/zhaochuninhefei/fabric-gm/common/genesis"
	"gitee.com/zhaochuninhefei/fabric-gm/core/config/configtest"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/configtxgen/encoder"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/configtxgen/genesisconfig"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/pkg/txflags"
	"gitee.com/zhaochuninhefei/fabric-gm/protoutil"
	cb "gitee.com/zhaochuninhefei/fabric-protos-go-gm/common"
	mspproto "gitee.com/zhaochuninhefei/fabric-protos-go-gm/msp"
	"gitee.com/zhaochuninhefei/fabric-protos-go-gm/peer"
	pb "gitee.com/zhaochuninhefei/fabric-protos-go-gm/peer"
)

var logger = flogging.MustGetLogger("common.configtx.test")

// MakeGenesisBlock creates a genesis block using the test templates for the given channelID
func MakeGenesisBlock(channelID string) (*cb.Block, error) {
	profile := genesisconfig.Load(genesisconfig.SampleDevModeSoloProfile, configtest.GetDevConfigDir())
	channelGroup, err := encoder.NewChannelGroup(profile)
	if err != nil {
		logger.Panicf("Error creating channel config: %s", err)
	}

	gb := genesis.NewFactoryImpl(channelGroup).Block(channelID)
	if gb == nil {
		return gb, nil
	}

	txsFilter := txflags.NewWithValues(len(gb.Data.Data), peer.TxValidationCode_VALID)
	gb.Metadata.Metadata[cb.BlockMetadataIndex_TRANSACTIONS_FILTER] = txsFilter

	return gb, nil
}

// MakeGenesisBlockWithMSPs creates a genesis block using the MSPs provided for the given channelID
func MakeGenesisBlockFromMSPs(channelID string, appMSPConf, ordererMSPConf *mspproto.MSPConfig, appOrgID, ordererOrgID string) (*cb.Block, error) {
	profile := genesisconfig.Load(genesisconfig.SampleDevModeSoloProfile, configtest.GetDevConfigDir())
	profile.Orderer.Organizations = nil
	channelGroup, err := encoder.NewChannelGroup(profile)
	if err != nil {
		logger.Panicf("Error creating channel config: %s", err)
	}

	ordererOrg := protoutil.NewConfigGroup()
	ordererOrg.ModPolicy = channelconfig.AdminsPolicyKey
	ordererOrg.Values[channelconfig.MSPKey] = &cb.ConfigValue{
		Value:     protoutil.MarshalOrPanic(channelconfig.MSPValue(ordererMSPConf).Value()),
		ModPolicy: channelconfig.AdminsPolicyKey,
	}

	applicationOrg := protoutil.NewConfigGroup()
	applicationOrg.ModPolicy = channelconfig.AdminsPolicyKey
	applicationOrg.Values[channelconfig.MSPKey] = &cb.ConfigValue{
		Value:     protoutil.MarshalOrPanic(channelconfig.MSPValue(appMSPConf).Value()),
		ModPolicy: channelconfig.AdminsPolicyKey,
	}
	applicationOrg.Values[channelconfig.AnchorPeersKey] = &cb.ConfigValue{
		Value:     protoutil.MarshalOrPanic(channelconfig.AnchorPeersValue([]*pb.AnchorPeer{}).Value()),
		ModPolicy: channelconfig.AdminsPolicyKey,
	}

	channelGroup.Groups[channelconfig.OrdererGroupKey].Groups[ordererOrgID] = ordererOrg
	channelGroup.Groups[channelconfig.ApplicationGroupKey].Groups[appOrgID] = applicationOrg

	return genesis.NewFactoryImpl(channelGroup).Block(channelID), nil
}
