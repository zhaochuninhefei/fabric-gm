/*
Copyright State Street Corp. 2018 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package channelconfig

import (
	"testing"

	pb "gitee.com/zhaochuninhefei/fabric-protos-go-gm/peer"
	"github.com/stretchr/testify/assert"
)

const (
	sampleAPI1Name      = "Foo"
	sampleAPI1PolicyRef = "foo"

	sampleAPI2Name      = "Bar"
	sampleAPI2PolicyRef = "/Channel/foo"
)

var sampleAPIsProvider = map[string]*pb.APIResource{
	sampleAPI1Name: {PolicyRef: sampleAPI1PolicyRef},
	sampleAPI2Name: {PolicyRef: sampleAPI2PolicyRef},
}

func TestGreenAPIsPath(t *testing.T) {
	ag := newAPIsProvider(sampleAPIsProvider)
	assert.NotNil(t, ag)

	t.Run("PresentAPIs", func(t *testing.T) {
		assert.Equal(t, "/Channel/Application/"+sampleAPI1PolicyRef, ag.PolicyRefForAPI(sampleAPI1Name))
		assert.Equal(t, sampleAPI2PolicyRef, ag.PolicyRefForAPI(sampleAPI2Name))
	})

	t.Run("MissingAPIs", func(t *testing.T) {
		assert.Empty(t, ag.PolicyRefForAPI("missing"))
	})
}

func TestNilACLs(t *testing.T) {
	ccg := newAPIsProvider(nil)

	assert.NotNil(t, ccg)
	assert.NotNil(t, ccg.aclPolicyRefs)
	assert.Empty(t, ccg.aclPolicyRefs)
}

func TestEmptyACLs(t *testing.T) {
	ccg := newAPIsProvider(map[string]*pb.APIResource{})

	assert.NotNil(t, ccg)
	assert.NotNil(t, ccg.aclPolicyRefs)
	assert.Empty(t, ccg.aclPolicyRefs)
}

func TestEmptyPolicyRef(t *testing.T) {
	var ars = map[string]*pb.APIResource{
		"unsetAPI": {PolicyRef: ""},
	}

	ccg := newAPIsProvider(ars)

	assert.NotNil(t, ccg)
	assert.NotNil(t, ccg.aclPolicyRefs)
	assert.Empty(t, ccg.aclPolicyRefs)

	ars = map[string]*pb.APIResource{
		"unsetAPI": {PolicyRef: ""},
		"setAPI":   {PolicyRef: sampleAPI2PolicyRef},
	}

	ccg = newAPIsProvider(ars)

	assert.NotNil(t, ccg)
	assert.NotNil(t, ccg.aclPolicyRefs)
	assert.NotEmpty(t, ccg.aclPolicyRefs)
	assert.NotContains(t, ccg.aclPolicyRefs, sampleAPI1Name)

}
