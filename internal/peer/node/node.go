/*
Copyright IBM Corp. 2016 All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package node

import (
	"fmt"

	"gitee.com/zhaochuninhefei/fabric-gm/common/flogging"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/peer/common"
	"github.com/spf13/cobra"
)

const (
	nodeFuncName = "node"
	nodeCmdDes   = "Operate a peer node: start|reset|rollback|pause|resume|rebuild-dbs|upgrade-dbs."
)

var logger = flogging.MustGetLogger("nodeCmd")

// Cmd returns the cobra command for Node
func Cmd() *cobra.Command {
	nodeCmd.AddCommand(startCmd())
	nodeCmd.AddCommand(resetCmd())
	nodeCmd.AddCommand(rollbackCmd())
	nodeCmd.AddCommand(pauseCmd())
	nodeCmd.AddCommand(resumeCmd())
	nodeCmd.AddCommand(rebuildDBsCmd())
	nodeCmd.AddCommand(upgradeDBsCmd())
	return nodeCmd
}

var nodeCmd = &cobra.Command{
	Use:              nodeFuncName,
	Short:            fmt.Sprint(nodeCmdDes),
	Long:             fmt.Sprint(nodeCmdDes),
	PersistentPreRun: common.InitCmd,
}
