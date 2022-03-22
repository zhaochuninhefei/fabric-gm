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
	"errors"
	"fmt"
	"reflect"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/utils"
	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/x509"
)

/*
 * bccsp/gm/keyimport.go 实现`gm.KeyImporter`接口(bccsp/gm/internals.go)
 */

//实现内部的 KeyImporter 接口
type gmsm4ImportKeyOptsKeyImporter struct{}

// 导入sm4密钥
// raw是密钥字节流，opts是扩展用字段，目前没有使用
func (*gmsm4ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	sm4Raw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("invalid raw material. Expected byte array")
	}

	if sm4Raw == nil {
		return nil, errors.New("invalid raw material. It must not be nil")
	}

	return &gmsm4Key{utils.Clone(sm4Raw), false}, nil
}

type gmsm2PrivateKeyImportOptsKeyImporter struct{}

// 导入sm2私钥
// raw是pkcs8标准的密钥字节流，opts是扩展用字段，目前没有使用
func (*gmsm2PrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {

	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[GMSM2PrivateKeyImportOpts] Invalid raw material. Expected byte array")
	}

	if len(der) == 0 {
		return nil, errors.New("[GMSM2PrivateKeyImportOpts] Invalid raw. It must not be nil")
	}

	// lowLevelKey, err := utils.DERToPrivateKey(der)
	// if err != nil {
	// 	return nil, fmt.Errorf("Failed converting PKIX to SM2 public key [%s]", err)
	// }

	// gmsm2SK, ok := lowLevelKey.(*sm2.PrivateKey)
	// if !ok {
	// 	return nil, errors.New("Failed casting to SM2 private key. Invalid raw material.")
	// }
	// 没有直接使用ParseSm2PrivateKey是因为这里需要raw是pkcs8标准的密钥字节流
	gmsm2SK, err := x509.ParsePKCS8UnecryptedPrivateKey(der)

	if err != nil {
		return nil, fmt.Errorf("failed converting to SM2 private key [%s]", err)
	}

	return &gmsm2PrivateKey{gmsm2SK}, nil
}

type gmsm2PublicKeyImportOptsKeyImporter struct{}

// 导入sm2公钥
// raw是PKIX标准的sm2公钥字节流，opts是扩展用字段，目前没有使用
func (*gmsm2PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[GMSM2PublicKeyImportOpts] Invalid raw material. Expected byte array")
	}

	if len(der) == 0 {
		return nil, errors.New("[GMSM2PublicKeyImportOpts] Invalid raw. It must not be nil")
	}

	// lowLevelKey, err := utils.DERToPrivateKey(der)
	// if err != nil {
	// 	return nil, fmt.Errorf("Failed converting PKIX to SM2 public key [%s]", err)
	// }

	// gmsm2SK, ok := lowLevelKey.(*sm2.PrivateKey)
	// if !ok {
	// 	return nil, errors.New("Failed casting to SM2 private key. Invalid raw material.")
	// }

	gmsm2SK, err := x509.ParseSm2PublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed converting to SM2 public key [%s]", err)
	}

	return &gmsm2PublicKey{gmsm2SK}, nil
}

type x509PublicKeyImportOptsKeyImporter struct {
	bccsp *impl
}

type ecdsaGoPublicKeyImportOptsKeyImporter struct{}

// 导入ecdsa公钥
// raw是Go内建的ecdsa公钥的字节流，opts是扩展用字段，目前没有使用
func (*ecdsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	lowLevelKey, ok := raw.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid raw material. Expected *ecdsa.PublicKey")
	}

	return &ecdsaPublicKey{lowLevelKey}, nil
}

type ecdsaPrivateKeyImportOptsKeyImporter struct{}

// 导入ecdsa私钥
// raw是PKCS1/PKCS8/EC格式的ecdsa私钥字节流，opts是扩展用字段，目前没有使用
func (*ecdsaPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw material. Expected byte array")
	}

	if len(der) == 0 {
		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw. It must not be nil")
	}

	lowLevelKey, err := utils.DERToPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaSK, ok := lowLevelKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed casting to ECDSA private key. Invalid raw material")
	}

	return &ecdsaPrivateKey{ecdsaSK}, nil
}

type ecdsaPKIXPublicKeyImportOptsKeyImporter struct{}

// 导入ecdsa公钥
// raw是PKIX标准的ecdsa公钥字节流，opts是扩展用字段，目前没有使用
func (*ecdsaPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("invalid raw material. Expected byte array")
	}

	if len(der) == 0 {
		return nil, errors.New("invalid raw. It must not be nil")
	}

	lowLevelKey, err := utils.DERToPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed converting PKIX to ECDSA public key [%s]", err)
	}

	ecdsaPK, ok := lowLevelKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed casting to ECDSA public key. Invalid raw material")
	}

	return &ecdsaPublicKey{ecdsaPK}, nil
}

// 导入gmx509公钥
// raw是国密x509证书
func (ki *x509PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {

	sm2Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, errors.New("invalid raw material. Expected *x509.Certificate")
	}

	pk := sm2Cert.PublicKey
	switch pk := pk.(type) {
	case sm2.PublicKey:
		fmt.Printf("bccsp gm keyimport pk is sm2.PublicKey")
		// sm2PublickKey, ok := pk.(sm2.PublicKey)
		// if !ok {
		// 	return nil, errors.New("Parse interface []  to sm2 pk error")
		// }
		// 将sm2公钥转为PKIX标准的sm2公钥字节流
		der, err := x509.MarshalSm2PublicKey(&pk)
		if err != nil {
			return nil, errors.New("MarshalSm2PublicKey error")
		}
		return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.SM2PublicKeyImportOpts{})].KeyImport(
			der,
			&bccsp.SM2PublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case *sm2.PublicKey:
		fmt.Printf("bccsp gm keyimport pk is *sm2.PublicKey")
		// TODO 逻辑没有问题吗？不应该和`case sm2.PublicKey`分支一样，先转为der吗？
		// return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.GMSM2PublicKeyImportOpts{})].KeyImport(
		// 	pk,
		// 	&bccsp.GMSM2PublicKeyImportOpts{Temporary: opts.Ephemeral()})
		der, err := x509.MarshalSm2PublicKey(pk)
		if err != nil {
			return nil, errors.New("MarshalSm2PublicKey error")
		}
		return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.SM2PublicKeyImportOpts{})].KeyImport(
			der,
			&bccsp.SM2PublicKeyImportOpts{Temporary: opts.Ephemeral()})
	case *ecdsa.PublicKey:
		// 这里没有先转为PKIX标准的公钥字节流，是因为使用的是ECDSAGoPublicKeyImportOpts
		return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	default:
		return nil, errors.New("certificate's public key type not recognized. Supported keys: [SM2]")
	}

	// return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.GMSM2PublicKeyImportOpts{})].KeyImport(
	// 	pk,
	// 	&bccsp.GMSM2PublicKeyImportOpts{Temporary:opts.Ephemeral()})

	// switch pk.(type) {
	// case *sm2.PublicKey:

	// 	ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.GMSM2PublicKeyImportOpts{})].KeyImport(
	// 		pk,
	// 		&bccsp.GMSM2PublicKeyImportOpts{Temporary:opts.Ephemeral()})

	// 	// return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.GMSM2PublicKeyImportOpts{})].KeyImport(
	// 	// 	pk,
	// 	// 	&bccsp.GMSM2PublicKeyImportOpts{Temporary: opts.Ephemeral()})
	// // case *rsa.PublicKey:
	// // 	return ki.bccsp.keyImporters[reflect.TypeOf(&bccsp.RSAGoPublicKeyImportOpts{})].KeyImport(
	// // 		pk,
	// // 		&bccsp.RSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	// default:
	// 	return nil, errors.New("Certificate's public key type not recognized. Supported keys: [ECDSA, RSA]")
	// }
}
