/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package channelconfig

import (
	"testing"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/sw"
	"gitee.com/zhaochuninhefei/fabric-gm/msp"
	cb "gitee.com/zhaochuninhefei/fabric-protos-go-gm/common"
	"github.com/stretchr/testify/assert"
)

func TestConsortiumConfig(t *testing.T) {
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)
	cc, err := NewConsortiumConfig(&cb.ConfigGroup{}, NewMSPConfigHandler(msp.MSPv1_0, cryptoProvider))
	assert.NoError(t, err)
	orgs := cc.Organizations()
	assert.Equal(t, 0, len(orgs))

	policy := cc.ChannelCreationPolicy()
	assert.EqualValues(t, cb.Policy_UNKNOWN, policy.Type, "Expected policy type to be UNKNOWN")
}
