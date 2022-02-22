/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mgmt

import (
	"testing"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/sw"
	"gitee.com/zhaochuninhefei/fabric-gm/core/config/configtest"
	"github.com/stretchr/testify/assert"
)

func TestLocalMSP(t *testing.T) {
	mspDir := configtest.GetDevMspDir()
	err := LoadLocalMsp(mspDir, nil, "SampleOrg")
	if err != nil {
		t.Fatalf("LoadLocalMsp failed, err %s", err)
	}

	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)
	_, err = GetLocalMSP(cryptoProvider).GetDefaultSigningIdentity()
	if err != nil {
		t.Fatalf("GetDefaultSigningIdentity failed, err %s", err)
	}
}
