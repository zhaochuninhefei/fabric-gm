/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package decorator

import (
	"gitee.com/zhaochuninhefei/fabric-gm/core/handlers/decoration"
	"gitee.com/zhaochuninhefei/fabric-protos-go-gm/peer"
)

// NewDecorator creates a new decorator
func NewDecorator() decoration.Decorator {
	return &decorator{}
}

type decorator struct {
}

// Decorate decorates a chaincode input by changing it
func (d *decorator) Decorate(proposal *peer.Proposal, input *peer.ChaincodeInput) *peer.ChaincodeInput {
	return input
}
