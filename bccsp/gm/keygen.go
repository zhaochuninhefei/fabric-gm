/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

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
package gm

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
	"gitee.com/zhaochuninhefei/gmgo/sm2"
)

/*
 * bccsp/gm/keygen.go 实现`gm.KeyGenerator`接口(bccsp/gm/internals.go)
 */

// 定义国密SM2 keygen 结构体，实现 KeyGenerator 接口
type gmsm2KeyGenerator struct {
}

// 生成sm2私钥
func (gm *gmsm2KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// 生成sm2私钥
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating SM2 key  [%s]", err)
	}

	return &gmsm2PrivateKey{privKey}, nil
}

// 定义 gmecdsaKeyGenerator 结构体，实现 KeyGenerator 接口
type gmecdsaKeyGenerator struct {
}

// 生成 gmecdsa 私钥，实际就是sm2私钥
func (gm *gmecdsaKeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// 生成sm2私钥
	privKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed generating SM2 key  [%s]", err)
	}
	// 另外定义一个 ecdsa.PrivateKey ，将sm2私钥的所有属性设置给它
	ecdsaPrivKey := &ecdsa.PrivateKey{}
	ecdsaPrivKey.Curve = privKey.Curve
	ecdsaPrivKey.D = privKey.D
	ecdsaPrivKey.X = privKey.X
	ecdsaPrivKey.Y = privKey.Y

	return &ecdsaPrivateKey{ecdsaPrivKey}, nil
}

// 定义国密SM4 keygen 结构体，实现 KeyGenerator 接口
type gmsm4KeyGenerator struct {
	length int
}

// 生成sm4密钥
func (kg *gmsm4KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// 生成sm4密钥
	lowLevelKey, err := GetRandomBytes(int(kg.length))
	if err != nil {
		return nil, fmt.Errorf("failed generating SM4 %d key [%s]", kg.length, err)
	}

	return &gmsm4Key{lowLevelKey, false}, nil
}
