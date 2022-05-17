/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"
	"strings"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/factory"
	"gitee.com/zhaochuninhefei/fabric-gm/cmd"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/peer/chaincode"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/peer/channel"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/peer/common"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/peer/lifecycle"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/peer/node"
	"gitee.com/zhaochuninhefei/fabric-gm/internal/peer/version"
	_ "gitee.com/zhaochuninhefei/gmgo/gmhttp/pprof"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// The main command describes the service and
// defaults to printing the help message.
var mainCmd = &cobra.Command{Use: "peer"}

func main() {
	// 检查zclog日志级别并设置
	cmd.CheckZclogLevelFromOsArgs()
	// For environment variables.
	viper.SetEnvPrefix(common.CmdRoot)
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	// Define command-line flags that are valid for all peer commands and
	// subcommands.
	mainFlags := mainCmd.PersistentFlags()

	mainFlags.String("logging-level", "", "Legacy logging level flag")
	viper.BindPFlag("logging_level", mainFlags.Lookup("logging-level"))
	mainFlags.MarkHidden("logging-level")

	cryptoProvider := factory.GetDefault()

	mainCmd.AddCommand(version.Cmd())
	mainCmd.AddCommand(node.Cmd())
	mainCmd.AddCommand(chaincode.Cmd(nil, cryptoProvider))
	mainCmd.AddCommand(channel.Cmd(nil))
	mainCmd.AddCommand(lifecycle.Cmd(cryptoProvider))

	// On failure Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if mainCmd.Execute() != nil {
		os.Exit(1)
	}
}
