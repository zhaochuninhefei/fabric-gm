// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	"sync"

	"gitee.com/zhaochuninhefei/fabric-gm/common/channelconfig"
	"gitee.com/zhaochuninhefei/fabric-gm/core/chaincode/lifecycle"
)

type ChannelConfigSource struct {
	GetStableChannelConfigStub        func(string) channelconfig.Resources
	getStableChannelConfigMutex       sync.RWMutex
	getStableChannelConfigArgsForCall []struct {
		arg1 string
	}
	getStableChannelConfigReturns struct {
		result1 channelconfig.Resources
	}
	getStableChannelConfigReturnsOnCall map[int]struct {
		result1 channelconfig.Resources
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *ChannelConfigSource) GetStableChannelConfig(arg1 string) channelconfig.Resources {
	fake.getStableChannelConfigMutex.Lock()
	ret, specificReturn := fake.getStableChannelConfigReturnsOnCall[len(fake.getStableChannelConfigArgsForCall)]
	fake.getStableChannelConfigArgsForCall = append(fake.getStableChannelConfigArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("GetStableChannelConfig", []interface{}{arg1})
	fake.getStableChannelConfigMutex.Unlock()
	if fake.GetStableChannelConfigStub != nil {
		return fake.GetStableChannelConfigStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.getStableChannelConfigReturns
	return fakeReturns.result1
}

func (fake *ChannelConfigSource) GetStableChannelConfigCallCount() int {
	fake.getStableChannelConfigMutex.RLock()
	defer fake.getStableChannelConfigMutex.RUnlock()
	return len(fake.getStableChannelConfigArgsForCall)
}

func (fake *ChannelConfigSource) GetStableChannelConfigCalls(stub func(string) channelconfig.Resources) {
	fake.getStableChannelConfigMutex.Lock()
	defer fake.getStableChannelConfigMutex.Unlock()
	fake.GetStableChannelConfigStub = stub
}

func (fake *ChannelConfigSource) GetStableChannelConfigArgsForCall(i int) string {
	fake.getStableChannelConfigMutex.RLock()
	defer fake.getStableChannelConfigMutex.RUnlock()
	argsForCall := fake.getStableChannelConfigArgsForCall[i]
	return argsForCall.arg1
}

func (fake *ChannelConfigSource) GetStableChannelConfigReturns(result1 channelconfig.Resources) {
	fake.getStableChannelConfigMutex.Lock()
	defer fake.getStableChannelConfigMutex.Unlock()
	fake.GetStableChannelConfigStub = nil
	fake.getStableChannelConfigReturns = struct {
		result1 channelconfig.Resources
	}{result1}
}

func (fake *ChannelConfigSource) GetStableChannelConfigReturnsOnCall(i int, result1 channelconfig.Resources) {
	fake.getStableChannelConfigMutex.Lock()
	defer fake.getStableChannelConfigMutex.Unlock()
	fake.GetStableChannelConfigStub = nil
	if fake.getStableChannelConfigReturnsOnCall == nil {
		fake.getStableChannelConfigReturnsOnCall = make(map[int]struct {
			result1 channelconfig.Resources
		})
	}
	fake.getStableChannelConfigReturnsOnCall[i] = struct {
		result1 channelconfig.Resources
	}{result1}
}

func (fake *ChannelConfigSource) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getStableChannelConfigMutex.RLock()
	defer fake.getStableChannelConfigMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *ChannelConfigSource) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ lifecycle.ChannelConfigSource = new(ChannelConfigSource)
