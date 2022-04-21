/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	validation "gitee.com/zhaochuninhefei/fabric-gm/core/handlers/validation/api"
	"gitee.com/zhaochuninhefei/fabric-protos-go-gm/common"
)

// NoOpValidator is used to test validation plugin infrastructure
type NoOpValidator struct {
}

// Validate valides the transactions with the given data
func (*NoOpValidator) Validate(_ *common.Block, _ string, _ int, _ int, _ ...validation.ContextDatum) error {
	return nil
}

// Init initializes the plugin with the given dependencies
func (*NoOpValidator) Init(dependencies ...validation.Dependency) error {
	return nil
}

// NoOpValidatorFactory creates new NoOpValidators
type NoOpValidatorFactory struct {
}

// New returns an instance of a NoOpValidator
func (*NoOpValidatorFactory) New() validation.Plugin {
	return &NoOpValidator{}
}

// NewPluginFactory is called by the validation plugin framework to obtain an instance
// of the factory
func NewPluginFactory() validation.PluginFactory {
	return &NoOpValidatorFactory{}
}
