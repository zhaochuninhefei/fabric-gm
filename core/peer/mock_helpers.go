/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/sw"
	"gitee.com/zhaochuninhefei/fabric-gm/common/channelconfig"
	configtxtest "gitee.com/zhaochuninhefei/fabric-gm/common/configtx/test"
	"gitee.com/zhaochuninhefei/fabric-gm/core/ledger"
)

func CreateMockChannel(p *Peer, cid string, resources channelconfig.Resources) error {
	var ledger ledger.PeerLedger
	var err error

	if ledger = p.GetLedger(cid); ledger == nil {
		gb, _ := configtxtest.MakeGenesisBlock(cid)
		if ledger, err = p.LedgerMgr.CreateLedger(cid, gb); err != nil {
			return err
		}
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.channels == nil {
		p.channels = map[string]*Channel{}
	}

	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	if err != nil {
		return err
	}

	p.channels[cid] = &Channel{
		ledger:         ledger,
		resources:      resources,
		cryptoProvider: cryptoProvider,
	}

	return nil
}
