/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ledgermgmttest

import (
	"fmt"
	"path/filepath"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/sw"
	"gitee.com/zhaochuninhefei/fabric-gm/common/metrics/disabled"
	"gitee.com/zhaochuninhefei/fabric-gm/core/ledger"
	"gitee.com/zhaochuninhefei/fabric-gm/core/ledger/ledgermgmt"
	"gitee.com/zhaochuninhefei/fabric-gm/core/ledger/mock"
)

// NewInitializer returns an instance of ledgermgmt Initializer
// with minimum fields populated so as not to cause a failure during construction of LedgerMgr.
// This is intended to be used for creating an instance of LedgerMgr for testing
func NewInitializer(testLedgerDir string) *ledgermgmt.Initializer {
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	if err != nil {
		panic(fmt.Errorf("Failed to initialize cryptoProvider bccsp: %s", err))
	}

	return &ledgermgmt.Initializer{
		Config: &ledger.Config{
			RootFSPath: testLedgerDir,
			// empty StateDBConfig means leveldb
			StateDBConfig: &ledger.StateDBConfig{},
			HistoryDBConfig: &ledger.HistoryDBConfig{
				Enabled: false,
			},
			PrivateDataConfig: &ledger.PrivateDataConfig{
				MaxBatchSize:    5000,
				BatchesInterval: 1000,
				PurgeInterval:   100,
			},
			SnapshotsConfig: &ledger.SnapshotsConfig{
				RootDir: filepath.Join(testLedgerDir, "snapshots"),
			},
		},
		MetricsProvider:                 &disabled.Provider{},
		DeployedChaincodeInfoProvider:   &mock.DeployedChaincodeInfoProvider{},
		HashProvider:                    cryptoProvider,
		HealthCheckRegistry:             &mock.HealthCheckRegistry{},
		ChaincodeLifecycleEventProvider: &mock.ChaincodeLifecycleEventProvider{},
	}
}
