/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/factory"
	"gitee.com/zhaochuninhefei/fabric-gm/cmd/common"
	discovery "gitee.com/zhaochuninhefei/fabric-gm/discovery/cmd"
)

func main() {
	factory.InitFactories(nil)
	cli := common.NewCLI("discover", "Command line client for fabric discovery service")
	discovery.AddCommands(cli)
	cli.Run(os.Args[1:])
}
