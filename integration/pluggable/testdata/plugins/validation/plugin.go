/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	validation "gitee.com/zhaochuninhefei/fabric-gm/core/handlers/validation/api"
	"gitee.com/zhaochuninhefei/fabric-gm/core/handlers/validation/builtin"
	"gitee.com/zhaochuninhefei/fabric-gm/integration/pluggable"
)

// go build -buildmode=plugin -o plugin.so

// NewPluginFactory is the function ran by the plugin infrastructure to create a validation plugin factory.
func NewPluginFactory() validation.PluginFactory {
	pluggable.PublishValidationPluginActivation()
	return &builtin.DefaultValidationFactory{}
}
