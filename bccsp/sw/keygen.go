/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
	"gitee.com/zhaochuninhefei/gmgo/sm2"
)

/*
bccsp/sw/keygen.go 定义各个算法的密钥生成器，实现`sw.KeyGenerator`接口(bccsp/sw/internals.go)
ecdsaKeyGenerator
sm2KeyGenerator
sm4KeyGenerator
aesKeyGenerator
*/

// ecdsa私钥生成器
type ecdsaKeyGenerator struct {
	curve elliptic.Curve
}

// 生成ecdsa私钥
func (kg *ecdsaKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := ecdsa.GenerateKey(kg.curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating ECDSA key for [%v]: [%s]", kg.curve, err)
	}

	return &ecdsaPrivateKey{privKey}, nil
}

// sm2私钥生成器
type sm2KeyGenerator struct {
}

// 生成sm2私钥
func (gm *sm2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating SM2 key : [%s]", err)
	}
	return &sm2PrivateKey{privKey}, nil
}

// sm4密钥生成器
type sm4KeyGenerator struct {
	length int
}

// 生成sm4密钥
func (kg *sm4KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	lowLevelKey, err := GetRandomBytes(int(kg.length))
	if err != nil {
		return nil, fmt.Errorf("failed generating SM4 %d key for : [%s]", kg.length, err)
	}
	return &sm4Key{lowLevelKey, true}, nil
}

// AES密钥生成器
type aesKeyGenerator struct {
	length int
}

// 生成AES密钥
func (kg *aesKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	lowLevelKey, err := GetRandomBytes(int(kg.length))
	if err != nil {
		return nil, fmt.Errorf("failed generating AES %d key [%s]", kg.length, err)
	}

	return &aesPrivateKey{lowLevelKey, false}, nil
}
