/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protoutil_test

import (
	"testing"

	"gitee.com/zhaochuninhefei/fabric-gm/protoutil"
	"gitee.com/zhaochuninhefei/fabric-protos-go-gm/common"
	"github.com/stretchr/testify/assert"
)

func TestNewConfigGroup(t *testing.T) {
	assert.Equal(t,
		&common.ConfigGroup{
			Groups:   make(map[string]*common.ConfigGroup),
			Values:   make(map[string]*common.ConfigValue),
			Policies: make(map[string]*common.ConfigPolicy),
		},
		protoutil.NewConfigGroup(),
	)
}
