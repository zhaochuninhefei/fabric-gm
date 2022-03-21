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
	ellipticCurve elliptic.Curve
	hashFunction  func() hash.Hash
	aesBitLength  int
	rsaBitLength  int
}

func (conf *config) setSecurityLevel(securityLevel int, hashFamily string) (err error) {
	switch hashFamily {
	case "SHA2":
		err = conf.setSecurityLevelSHA2(securityLevel)
	case "SHA3":
		err = conf.setSecurityLevelSHA3(securityLevel)
	case "SM3":
		// SM3时，直接使用SM2WithSM3
		// err = conf.setSecurityLevelGMSM3(securityLevel)
		err = conf.setSecurityLevelSM2WithSM3()
	default:
		err = fmt.Errorf("Hash Family not supported [%s]", hashFamily)
	}
	return
}

// func (conf *config) setSecurityLevelGMSM3(level int) (err error) {
// 	switch level {
// 	case 256:
// 		conf.ellipticCurve = elliptic.P256()
// 		conf.hashFunction = sm3.New
// 		conf.rsaBitLength = 2048
// 		conf.aesBitLength = 32
// 	case 384:
// 		conf.ellipticCurve = elliptic.P384()
// 		conf.hashFunction = sm3.New
// 		conf.rsaBitLength = 3072
// 		conf.aesBitLength = 32
// 	default:
// 		err = fmt.Errorf("security level not supported [%d]", level)
// 	}
// 	return
// }

func (conf *config) setSecurityLevelSM2WithSM3() (err error) {
	conf.ellipticCurve = sm2.P256Sm2()
	conf.hashFunction = sm3.New
	conf.rsaBitLength = 2048
	conf.aesBitLength = 32
	return nil
}

func (conf *config) setSecurityLevelSHA2(level int) (err error) {
	switch level {
	case 256:
		conf.ellipticCurve = elliptic.P256()
		conf.hashFunction = sha256.New
		conf.aesBitLength = 32
	case 384:
		conf.ellipticCurve = elliptic.P384()
		conf.hashFunction = sha512.New384
		conf.aesBitLength = 32
	default:
		err = fmt.Errorf("security level not supported [%d]", level)
	}
	return
}

func (conf *config) setSecurityLevelSHA3(level int) (err error) {
	switch level {
	case 256:
		conf.ellipticCurve = elliptic.P256()
		conf.hashFunction = sha3.New256
		conf.aesBitLength = 32
	case 384:
		conf.ellipticCurve = elliptic.P384()
		conf.hashFunction = sha3.New384
		conf.aesBitLength = 32
	default:
		err = fmt.Errorf("security level not supported [%d]", level)
	}
	return
}
