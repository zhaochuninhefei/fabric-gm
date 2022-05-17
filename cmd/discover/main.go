/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/factory"
	"gitee.com/zhaochuninhefei/fabric-gm/cmd"
	"gitee.com/zhaochuninhefei/fabric-gm/cmd/common"
	discovery "gitee.com/zhaochuninhefei/fabric-gm/discovery/cmd"
)

func main() {
	// 检查zclog日志级别并设置
	cmd.CheckZclogLevelFromOsArgs()
	factory.InitFactories(nil)
	cli := common.NewCLI("discover", "Command line client for fabric discovery service")
	discovery.AddCommands(cli)
	cli.Run(os.Args[1:])
}
