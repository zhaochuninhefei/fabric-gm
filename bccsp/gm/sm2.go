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
	// "crypto/ecdsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
	"gitee.com/zhaochuninhefei/gmgo/sm2"
)

/*
 * bccsp/gm/sm2.go 实现`gm.Signer`接口和`gm.Verifier`接口(bccsp/gm/internals.go)
 */

type SM2Signature struct {
	R, S *big.Int
}

var (
	// curveHalfOrders contains the precomputed curve group orders halved.
	// It is used to ensure that signature' S value is lower or equal to the
	// curve group order halved. We accept only low-S signatures.
	// They are precomputed for efficiency reasons.
	// 保存每条曲线的(N >> 1) 即，除2的结果
	curveHalfOrders map[elliptic.Curve]*big.Int = map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
		sm2.P256Sm2():   new(big.Int).Rsh(sm2.P256Sm2().Params().N, 1),
	}
)

// 对签名(r,s)做asn1编码
func MarshalSM2Signature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(SM2Signature{r, s})
}

// 对asn1编码的签名做解码
func UnmarshalSM2Signature(raw []byte) (*big.Int, *big.Int, error) {
	// Unmarshal
	sig := new(SM2Signature)
	_, err := asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed unmashalling signature [%s]", err)
	}

	// Validate sig
	if sig.R == nil {
		return nil, nil, errors.New("invalid signature. R must be different from nil")
	}
	if sig.S == nil {
		return nil, nil, errors.New("invalid signature. S must be different from nil")
	}

	if sig.R.Sign() != 1 {
		return nil, nil, errors.New("invalid signature. R must be larger than zero")
	}
	if sig.S.Sign() != 1 {
		return nil, nil, errors.New("invalid signature. S must be larger than zero")
	}

	return sig.R, sig.S, nil
}

// 国密sm2签名，digest是明文不是摘要，opts实际没有使用
func signGMSM2(k *sm2.PrivateKey, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	signature, err = k.Sign(rand.Reader, digest, opts)
	return
}

// 国密sm2验签，digest是签名内容明文，signature是被验签的签名，opts实际没有使用
func verifyGMSM2(k *sm2.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	valid = k.Verify(digest, signature)
	return
}

type gmsm2Signer struct{}

// 在gmsm2Signer上绑定Sign签名方法
func (s *gmsm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	return signGMSM2(k.(*gmsm2PrivateKey).privKey, digest, opts)
}

type ecdsaPrivateKeySigner struct{}

// 在ecdsaPrivateKeySigner上绑定Sign签名方法，内部转为sm2签名。
// 注意，k明面上是ecdsa私钥，但其实内部所有参数都是sm2的参数(Curve、X、Y、D)。
func (s *ecdsaPrivateKeySigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// 如果k的类型不是`ecdsaPrivateKey`，比如是`gmsm2PrivateKey`，那么这里会出错。
	// 但后续又将ecdsaPrivateKey的Curve、X、Y、D直接拿来当作sm2.PublicKey与sm2.PrivateKey的相关参数，
	// 因此必须满足条件：k是使用`gm.gmecdsaKeyGenerator`(bccsp/gm/ecdsakey.go)的`KeyGen`方法生成的ecdsa私钥。
	// 这样，k明面上是ecdsa私钥，但其实内部所有参数都是sm2的。
	puk := k.(*ecdsaPrivateKey).privKey.PublicKey
	sm2pk := sm2.PublicKey{
		Curve: puk.Curve,
		X:     puk.X,
		Y:     puk.Y,
	}
	privKey := k.(*ecdsaPrivateKey).privKey
	sm2privKey := sm2.PrivateKey{
		D:         privKey.D,
		PublicKey: sm2pk,
	}
	return signGMSM2(&sm2privKey, digest, opts)
}

type gmsm2PrivateKeyVerifier struct{}

// 在gmsm2PrivateKeyVerifier上绑定验签方法
func (v *gmsm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifyGMSM2(&(k.(*gmsm2PrivateKey).privKey.PublicKey), signature, digest, opts)
}

type gmsm2PublicKeyKeyVerifier struct{}

// 在gmsm2PublicKeyKeyVerifier上绑定验签方法
func (v *gmsm2PublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifyGMSM2(k.(*gmsm2PublicKey).pubKey, signature, digest, opts)
}

type ecdsaPrivateKeyVerifier struct{}

// 在ecdsaPrivateKeyVerifier上绑定Verify验签方法，内部转为sm2验签。
// 注意，k明面上是ecdsa私钥，但其实内部所有参数都是sm2的参数(Curve、X、Y、D)。
func (v *ecdsaPrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	puk := k.(*ecdsaPrivateKey).privKey.PublicKey
	sm2pk := sm2.PublicKey{
		Curve: puk.Curve,
		X:     puk.X,
		Y:     puk.Y,
	}
	return verifyGMSM2(&sm2pk, signature, digest, opts)
}

type ecdsaPublicKeyKeyVerifier struct{}

// 在ecdsaPublicKeyKeyVerifier上绑定Verify验签方法，内部转为sm2验签。
// 注意，k明面上是ecdsa公钥，但其实内部所有参数都是sm2的参数(Curve、X、Y)。
func (v *ecdsaPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	puk := k.(*ecdsaPublicKey).pubKey
	sm2pk := sm2.PublicKey{
		Curve: puk.Curve,
		X:     puk.X,
		Y:     puk.Y,
	}
	return verifyGMSM2(&sm2pk, signature, digest, opts)
}

// 将签名中的s改为lowS
// 该函数作用目前不明确
func SignatureToLowS(k *ecdsa.PublicKey, signature []byte) ([]byte, error) {
	r, s, err := UnmarshalSM2Signature(signature)
	if err != nil {
		return nil, err
	}

	s, modified, err := ToLowS(k, s)
	if err != nil {
		return nil, err
	}

	if modified {
		return MarshalSM2Signature(r, s)
	}
	return signature, nil
}

func ToLowS(k *ecdsa.PublicKey, s *big.Int) (*big.Int, bool, error) {
	lowS, err := IsLowS(k, s)
	if err != nil {
		return nil, false, err
	}

	// 不是 lowS 且曲线不是sm2的椭圆曲线时，将s值改为 N-s
	if !lowS && k.Curve != sm2.P256Sm2() {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order
		s.Sub(k.Params().N, s)

		return s, true, nil
	}

	return s, false, nil
}

// IsLow checks that s is a low-S.
// low-S 的含义是 s 不比 halfOrder 大。
// halfOrder 是椭圆曲线参数N的一半。
func IsLowS(k *ecdsa.PublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := curveHalfOrders[k.Curve]
	if !ok {
		return false, fmt.Errorf("curve not recognized [%s]", k.Curve)
	}
	// 判断s是否<=halfOrder
	return s.Cmp(halfOrder) != 1, nil

}
