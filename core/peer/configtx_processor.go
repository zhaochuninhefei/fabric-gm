/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"

	"gitee.com/zhaochuninhefei/fabric-gm/core/ledger"
	"gitee.com/zhaochuninhefei/fabric-gm/protoutil"
	"gitee.com/zhaochuninhefei/fabric-protos-go-gm/common"
	"github.com/golang/protobuf/proto"
)

const (
	channelConfigKey = "CHANNEL_CONFIG_ENV_BYTES"
	peerNamespace    = ""
)

// ConfigTxProcessor implements the interface 'gitee.com/zhaochuninhefei/fabric-gm/core/ledger/customtx/Processor'
type ConfigTxProcessor struct{}

// GenerateSimulationResults implements function in the interface 'gitee.com/zhaochuninhefei/fabric-gm/core/ledger/customtx/Processor'
// This implementation processes CONFIG transactions which simply stores the config-envelope-bytes
func (tp *ConfigTxProcessor) GenerateSimulationResults(txEnv *common.Envelope, simulator ledger.TxSimulator, initializingLedger bool) error {
	payload := protoutil.UnmarshalPayloadOrPanic(txEnv.Payload)
	channelHdr := protoutil.UnmarshalChannelHeaderOrPanic(payload.Header.ChannelHeader)
	txType := common.HeaderType(channelHdr.GetType())

	switch txType {
	case common.HeaderType_CONFIG:
		peerLogger.Debugf("Processing CONFIG")
		if payload.Data == nil {
			return fmt.Errorf("channel config found nil")
		}
		return simulator.SetState(peerNamespace, channelConfigKey, payload.Data)
	default:
		return fmt.Errorf("tx type [%s] is not expected", txType)
	}
}

func retrieveChannelConfig(queryExecuter ledger.QueryExecutor) (*common.Config, error) {
	configBytes, err := queryExecuter.GetState(peerNamespace, channelConfigKey)
	if err != nil {
		return nil, err
	}
	if configBytes == nil {
		return nil, nil
	}
	configEnvelope := &common.ConfigEnvelope{}
	if err := proto.Unmarshal(configBytes, configEnvelope); err != nil {
		return nil, err
	}
	return configEnvelope.Config, nil
}
