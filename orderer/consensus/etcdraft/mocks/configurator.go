// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"

	"gitee.com/zhaochuninhefei/fabric-gm/orderer/common/cluster"
	"gitee.com/zhaochuninhefei/fabric-gm/orderer/consensus/etcdraft"
)

type FakeConfigurator struct {
	ConfigureStub        func(string, []cluster.RemoteNode)
	configureMutex       sync.RWMutex
	configureArgsForCall []struct {
		arg1 string
		arg2 []cluster.RemoteNode
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeConfigurator) Configure(arg1 string, arg2 []cluster.RemoteNode) {
	var arg2Copy []cluster.RemoteNode
	if arg2 != nil {
		arg2Copy = make([]cluster.RemoteNode, len(arg2))
		copy(arg2Copy, arg2)
	}
	fake.configureMutex.Lock()
	fake.configureArgsForCall = append(fake.configureArgsForCall, struct {
		arg1 string
		arg2 []cluster.RemoteNode
	}{arg1, arg2Copy})
	fake.recordInvocation("Configure", []interface{}{arg1, arg2Copy})
	fake.configureMutex.Unlock()
	if fake.ConfigureStub != nil {
		fake.ConfigureStub(arg1, arg2)
	}
}

func (fake *FakeConfigurator) ConfigureCallCount() int {
	fake.configureMutex.RLock()
	defer fake.configureMutex.RUnlock()
	return len(fake.configureArgsForCall)
}

func (fake *FakeConfigurator) ConfigureCalls(stub func(string, []cluster.RemoteNode)) {
	fake.configureMutex.Lock()
	defer fake.configureMutex.Unlock()
	fake.ConfigureStub = stub
}

func (fake *FakeConfigurator) ConfigureArgsForCall(i int) (string, []cluster.RemoteNode) {
	fake.configureMutex.RLock()
	defer fake.configureMutex.RUnlock()
	argsForCall := fake.configureArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *FakeConfigurator) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.configureMutex.RLock()
	defer fake.configureMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeConfigurator) recordInvocation(key string, args []interface{}) {
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

var _ etcdraft.Configurator = new(FakeConfigurator)
