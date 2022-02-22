/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txvalidator_test

import (
	"testing"

	"gitee.com/zhaochuninhefei/fabric-gm/common/policydsl"
	tmocks "gitee.com/zhaochuninhefei/fabric-gm/core/committer/txvalidator/mocks"
	"gitee.com/zhaochuninhefei/fabric-gm/core/committer/txvalidator/plugin"
	"gitee.com/zhaochuninhefei/fabric-gm/core/committer/txvalidator/v14"
	"gitee.com/zhaochuninhefei/fabric-gm/core/committer/txvalidator/v14/mocks"
	"gitee.com/zhaochuninhefei/fabric-gm/core/committer/txvalidator/v14/testdata"
	validation "gitee.com/zhaochuninhefei/fabric-gm/core/handlers/validation/api"
	"gitee.com/zhaochuninhefei/fabric-gm/msp"
	. "gitee.com/zhaochuninhefei/fabric-gm/msp/mocks"
	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestValidateWithPlugin(t *testing.T) {
	pm := make(plugin.MapBasedMapper)
	qec := &mocks.QueryExecutorCreator{}
	deserializer := &mocks.IdentityDeserializer{}
	capabilities := &mocks.Capabilities{}
	v := txvalidator.NewPluginValidator(pm, qec, deserializer, capabilities)
	ctx := &txvalidator.Context{
		Namespace: "mycc",
		VSCCName:  "vscc",
	}

	// Scenario I: The plugin isn't found because the map wasn't populated with anything yet
	err := v.ValidateWithPlugin(ctx)
	assert.Contains(t, err.Error(), "plugin with name vscc wasn't found")

	// Scenario II: The plugin initialization fails
	factory := &mocks.PluginFactory{}
	plugin := &mocks.Plugin{}
	plugin.On("Init", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("foo")).Once()
	factory.On("New").Return(plugin)
	pm["vscc"] = factory
	err = v.ValidateWithPlugin(ctx)
	assert.Contains(t, err.(*validation.ExecutionFailureError).Error(), "failed initializing plugin: foo")

	// Scenario III: The plugin initialization succeeds but an execution error occurs.
	// The plugin should pass the error as is.
	plugin.On("Init", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	validationErr := &validation.ExecutionFailureError{
		Reason: "bar",
	}
	plugin.On("Validate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(validationErr).Once()
	err = v.ValidateWithPlugin(ctx)
	assert.Equal(t, validationErr, err)

	// Scenario IV: The plugin initialization succeeds and the validation passes
	plugin.On("Init", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	plugin.On("Validate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	err = v.ValidateWithPlugin(ctx)
	assert.NoError(t, err)
}

func TestSamplePlugin(t *testing.T) {
	pm := make(plugin.MapBasedMapper)

	qe := &tmocks.QueryExecutor{}
	state := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	qe.On("GetState", "lscc", "mycc").Return(state, nil)
	qe.On("GetStateMultipleKeys", "lscc", []string{"mycc"}).Return([][]byte{state}, nil)
	qe.On("Done").Return(nil, nil)

	qec := &mocks.QueryExecutorCreator{}
	qec.On("NewQueryExecutor").Return(qe, nil)

	deserializer := &mocks.IdentityDeserializer{}
	identity := &MockIdentity{}
	identity.On("GetIdentifier").Return(&msp.IdentityIdentifier{
		Mspid: "SampleOrg",
		Id:    "foo",
	})
	deserializer.On("DeserializeIdentity", []byte{7, 8, 9}).Return(identity, nil)
	capabilities := &mocks.Capabilities{}
	capabilities.On("PrivateChannelData").Return(true)
	factory := &mocks.PluginFactory{}
	factory.On("New").Return(testdata.NewSampleValidationPlugin(t))
	pm["vscc"] = factory

	transaction := testdata.MarshaledSignedData{
		Data:      []byte{1, 2, 3},
		Signature: []byte{4, 5, 6},
		Identity:  []byte{7, 8, 9},
	}

	txnData, _ := proto.Marshal(&transaction)

	v := txvalidator.NewPluginValidator(pm, qec, deserializer, capabilities)
	acceptAllPolicyBytes, _ := proto.Marshal(policydsl.AcceptAllPolicy)
	ctx := &txvalidator.Context{
		Namespace: "mycc",
		VSCCName:  "vscc",
		Policy:    acceptAllPolicyBytes,
		Block: &common.Block{
			Header: &common.BlockHeader{},
			Data: &common.BlockData{
				Data: [][]byte{txnData},
			},
		},
		Channel: "mychannel",
	}
	assert.NoError(t, v.ValidateWithPlugin(ctx))
}
