// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"gitee.com/zhaochuninhefei/fabric-gm/common/flogging/httpadmin"
)

type Logging struct {
	ActivateSpecStub        func(string) error
	activateSpecMutex       sync.RWMutex
	activateSpecArgsForCall []struct {
		arg1 string
	}
	activateSpecReturns struct {
		result1 error
	}
	activateSpecReturnsOnCall map[int]struct {
		result1 error
	}
	SpecStub        func() string
	specMutex       sync.RWMutex
	specArgsForCall []struct {
	}
	specReturns struct {
		result1 string
	}
	specReturnsOnCall map[int]struct {
		result1 string
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Logging) ActivateSpec(arg1 string) error {
	fake.activateSpecMutex.Lock()
	ret, specificReturn := fake.activateSpecReturnsOnCall[len(fake.activateSpecArgsForCall)]
	fake.activateSpecArgsForCall = append(fake.activateSpecArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("ActivateSpec", []interface{}{arg1})
	fake.activateSpecMutex.Unlock()
	if fake.ActivateSpecStub != nil {
		return fake.ActivateSpecStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.activateSpecReturns
	return fakeReturns.result1
}

func (fake *Logging) ActivateSpecCallCount() int {
	fake.activateSpecMutex.RLock()
	defer fake.activateSpecMutex.RUnlock()
	return len(fake.activateSpecArgsForCall)
}

func (fake *Logging) ActivateSpecCalls(stub func(string) error) {
	fake.activateSpecMutex.Lock()
	defer fake.activateSpecMutex.Unlock()
	fake.ActivateSpecStub = stub
}

func (fake *Logging) ActivateSpecArgsForCall(i int) string {
	fake.activateSpecMutex.RLock()
	defer fake.activateSpecMutex.RUnlock()
	argsForCall := fake.activateSpecArgsForCall[i]
	return argsForCall.arg1
}

func (fake *Logging) ActivateSpecReturns(result1 error) {
	fake.activateSpecMutex.Lock()
	defer fake.activateSpecMutex.Unlock()
	fake.ActivateSpecStub = nil
	fake.activateSpecReturns = struct {
		result1 error
	}{result1}
}

func (fake *Logging) ActivateSpecReturnsOnCall(i int, result1 error) {
	fake.activateSpecMutex.Lock()
	defer fake.activateSpecMutex.Unlock()
	fake.ActivateSpecStub = nil
	if fake.activateSpecReturnsOnCall == nil {
		fake.activateSpecReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.activateSpecReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *Logging) Spec() string {
	fake.specMutex.Lock()
	ret, specificReturn := fake.specReturnsOnCall[len(fake.specArgsForCall)]
	fake.specArgsForCall = append(fake.specArgsForCall, struct {
	}{})
	fake.recordInvocation("Spec", []interface{}{})
	fake.specMutex.Unlock()
	if fake.SpecStub != nil {
		return fake.SpecStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.specReturns
	return fakeReturns.result1
}

func (fake *Logging) SpecCallCount() int {
	fake.specMutex.RLock()
	defer fake.specMutex.RUnlock()
	return len(fake.specArgsForCall)
}

func (fake *Logging) SpecCalls(stub func() string) {
	fake.specMutex.Lock()
	defer fake.specMutex.Unlock()
	fake.SpecStub = stub
}

func (fake *Logging) SpecReturns(result1 string) {
	fake.specMutex.Lock()
	defer fake.specMutex.Unlock()
	fake.SpecStub = nil
	fake.specReturns = struct {
		result1 string
	}{result1}
}

func (fake *Logging) SpecReturnsOnCall(i int, result1 string) {
	fake.specMutex.Lock()
	defer fake.specMutex.Unlock()
	fake.SpecStub = nil
	if fake.specReturnsOnCall == nil {
		fake.specReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.specReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *Logging) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.activateSpecMutex.RLock()
	defer fake.activateSpecMutex.RUnlock()
	fake.specMutex.RLock()
	defer fake.specMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Logging) recordInvocation(key string, args []interface{}) {
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

var _ httpadmin.Logging = new(Logging)
