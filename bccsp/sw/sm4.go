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
package sw

import (
	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
	"gitee.com/zhaochuninhefei/gmgo/sm4"
)

/*
bccsp/sw/sm4.go 实现`sw.Encryptor`接口和`sw.Decryptor`接口(bccsp/sw/internals.go)
目前存在问题: 没有分组逻辑，直接调用了sm4对每组明文/密文的分组加解密函数。
*/

// GetRandomBytes returns len random looking bytes
// func GetRandomBytes(len int) ([]byte, error) {
// 	if len < 0 {
// 		return nil, errors.New("Len must be larger than 0")
// 	}

// 	buffer := make([]byte, len)

// 	n, err := rand.Read(buffer)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if n != len {
// 		return nil, fmt.Errorf("Buffer not filled. Requested [%d], got [%d]", len, n)
// 	}

// 	return buffer, nil
// }

// AESCBCPKCS7Encrypt combines CBC encryption and PKCS7 padding

// 直接调用sm4分组加密 分组在哪做?
func SM4Encrypt(key, src []byte) ([]byte, error) {
	// // First pad
	// tmp := pkcs7Padding(src)

	// // Then encrypt
	// return aesCBCEncrypt(key, tmp)
	dst := make([]byte, len(src))
	sm4.EncryptBlock(key, dst, src)
	return dst, nil
}

// AESCBCPKCS7Decrypt combines CBC decryption and PKCS7 unpadding

// 直接调用sm4分组解密 分组在哪做?
func SM4Decrypt(key, src []byte) ([]byte, error) {
	// First decrypt
	// pt, err := aesCBCDecrypt(key, src)
	// if err == nil {
	// 	return pkcs7UnPadding(pt)
	// }

	dst := make([]byte, len(src))
	sm4.DecryptBlock(key, dst, src)
	return dst, nil
}

type sm4Encryptor struct{}

// 实现 Encryptor 接口
// 不能直接调用 SM4Encrypt 因为没有分组
func (e *sm4Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	key := k.(*sm4Key).privKey
	switch o := opts.(type) {
	case *bccsp.SM4EncrypterDecrypterOpts:
		iv := o.IV
		switch o.MODE {
		case "ECB":
			return sm4.Sm4Ecb(key, plaintext, true)
		case "CBC":
			return sm4.Sm4Cbc(key, iv, plaintext, true)
		case "CFB":
			return sm4.Sm4CFB(key, iv, plaintext, true)
		case "OFB":
			return sm4.Sm4OFB(key, iv, plaintext, true)
		default:
			return sm4.Sm4Ecb(key, plaintext, true)
		}
	case bccsp.SM4EncrypterDecrypterOpts:
		return e.Encrypt(k, plaintext, &o)
	default:
		return e.Encrypt(k, plaintext, &bccsp.SM4EncrypterDecrypterOpts{})
	}
	// return SM4Encrypt(k.(*sm4Key).privKey, plaintext)
	//return AESCBCPKCS7Encrypt(k.(*sm4PrivateKey).privKey, plaintext)
	// key := k.(*sm4Key).privKey
	// var en = make([]byte, 16)
	// sms4(plaintext, 16, key, en, 1)
	// return en, nil
}

type sm4Decryptor struct{}

// 实现 Decryptor 接口
// 不能直接调用 SM4Decrypt 因为没有分组
func (e *sm4Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	key := k.(*sm4Key).privKey
	switch o := opts.(type) {
	case *bccsp.SM4EncrypterDecrypterOpts:
		iv := o.IV
		switch o.MODE {
		case "ECB":
			return sm4.Sm4Ecb(key, ciphertext, false)
		case "CBC":
			return sm4.Sm4Cbc(key, iv, ciphertext, false)
		case "CFB":
			return sm4.Sm4CFB(key, iv, ciphertext, false)
		case "OFB":
			return sm4.Sm4OFB(key, iv, ciphertext, false)
		default:
			return sm4.Sm4Ecb(key, ciphertext, false)
		}
	case bccsp.SM4EncrypterDecrypterOpts:
		return e.Decrypt(k, ciphertext, &o)
	default:
		return e.Decrypt(k, ciphertext, &bccsp.SM4EncrypterDecrypterOpts{})
	}
	// return SM4Decrypt(k.(*sm4Key).privKey, ciphertext)
	// var dc = make([]byte, 16)
	// key := k.(*sm4Key).privKey
	// sms4(ciphertext, 16, key, dc, 0)
	// return dc, nil
}
