/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package blocksprovider_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"gitee.com/zhaochuninhefei/fabric-gm/internal/pkg/identity"
	"gitee.com/zhaochuninhefei/fabric-protos-go-gm/orderer"
)

//go:generate counterfeiter -o fake/signer.go --fake-name Signer . signer
type signer interface {
	identity.SignerSerializer
}

//go:generate counterfeiter -o fake/ab_deliver_client.go --fake-name DeliverClient . abDeliverClient
type abDeliverClient interface {
	orderer.AtomicBroadcast_DeliverClient
}

func TestBlocksprovider(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Blocksprovider Suite")
}
