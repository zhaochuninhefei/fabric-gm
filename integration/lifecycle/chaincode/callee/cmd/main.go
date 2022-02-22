/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"

	"gitee.com/zhaochuninhefei/fabric-chaincode-go-gm/shim"
	"gitee.com/zhaochuninhefei/fabric-gm/integration/lifecycle/chaincode/callee"
)

func main() {
	err := shim.Start(&callee.CC{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Exiting callee chaincode: %s", err)
		os.Exit(2)
	}
}
