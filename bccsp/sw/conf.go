/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/sm3"
	"golang.org/x/crypto/sha3"
)

/*
bccsp/sw/conf.go 提供bccsp配置
*/

type config struct {
	// 椭圆曲线
	ellipticCurve elliptic.Curve
	// 散列函数
	hashFunction func() hash.Hash
	// sm4密钥位数
	sm4BitLength int
	// AES密钥位数
	aesBitLength int
	// RSA私钥位数
	rsaBitLength int
}

// 设置安全级别配置
// 当 securityLevel=256 且 hashFamily=SM3 时椭圆曲线使用P256Sm2
func (conf *config) setSecurityLevel(securityLevel int, hashFamily string) (err error) {
	switch hashFamily {
	case "SHA2":
		err = conf.setSecurityLevelSHA2(securityLevel)
	case "SHA3":
		err = conf.setSecurityLevelSHA3(securityLevel)
	case "SM3":
		if securityLevel == 256 {
			err = conf.setSecurityLevelWithSM2SM3()
		} else {
			err = conf.setSecurityLevelSM3(securityLevel)
		}
	default:
		err = fmt.Errorf("Hash Family not supported [%s]", hashFamily)
	}
	return
}

// 设置使用ecdsa与SHA2时的安全级别配置
func (conf *config) setSecurityLevelSHA2(level int) (err error) {
	switch level {
	case 256:
		conf.ellipticCurve = elliptic.P256()
		conf.hashFunction = sha256.New
		conf.rsaBitLength = 2048
		conf.aesBitLength = 32
		conf.sm4BitLength = 128
	case 384:
		conf.ellipticCurve = elliptic.P384()
		conf.hashFunction = sha512.New384
		conf.rsaBitLength = 3072
		conf.aesBitLength = 32
		conf.sm4BitLength = 128
	default:
		err = fmt.Errorf("security level not supported [%d]", level)
	}
	return
}

// 设置使用ecdsa与SHA3时的安全级别配置
func (conf *config) setSecurityLevelSHA3(level int) (err error) {
	switch level {
	case 256:
		conf.ellipticCurve = elliptic.P256()
		conf.hashFunction = sha3.New256
		conf.rsaBitLength = 2048
		conf.aesBitLength = 32
		conf.sm4BitLength = 128
	case 384:
		conf.ellipticCurve = elliptic.P384()
		conf.hashFunction = sha3.New384
		conf.rsaBitLength = 3072
		conf.aesBitLength = 32
		conf.sm4BitLength = 128
	default:
		err = fmt.Errorf("security level not supported [%d]", level)
	}
	return
}

// 设置使用ecdsa与sm3时的安全级别配置
func (conf *config) setSecurityLevelSM3(level int) (err error) {
	switch level {
	case 256:
		conf.ellipticCurve = elliptic.P256()
		conf.hashFunction = sm3.New
		conf.rsaBitLength = 2048
		conf.aesBitLength = 32
		conf.sm4BitLength = 128
	case 384:
		conf.ellipticCurve = elliptic.P384()
		conf.hashFunction = sm3.New
		conf.rsaBitLength = 3072
		conf.aesBitLength = 32
		conf.sm4BitLength = 128
	default:
		err = fmt.Errorf("security level not supported [%d]", level)
	}
	return
}

// 设置使用sm2与sm3时的安全级别配置
func (conf *config) setSecurityLevelWithSM2SM3() (err error) {
	conf.ellipticCurve = sm2.P256Sm2()
	conf.hashFunction = sm3.New
	conf.sm4BitLength = 128
	conf.rsaBitLength = 2048
	conf.aesBitLength = 32
	return nil
}
