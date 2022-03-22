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
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"reflect"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
	"gitee.com/zhaochuninhefei/fabric-gm/common/flogging"
	"gitee.com/zhaochuninhefei/gmgo/sm3"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

/*
 * bccsp/gm/impl.go 是对`bccsp.BCCSP`接口(bccsp/bccsp.go)的国密实现。
 * SM4的接口实现可能有问题，没有看到分组操作，而是直接调用了分组加解密。
 */

var (
	logger = flogging.MustGetLogger("bccsp_gm")
)

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// at security level 256, hash family SHA2 and using FolderBasedKeyStore as KeyStore.
func NewDefaultSecurityLevel(keyStorePath string) (bccsp.BCCSP, error) {
	ks := &fileBasedKeyStore{}
	if err := ks.Init(nil, keyStorePath, false); err != nil {
		return nil, errors.Wrapf(err, "Failed initializing key store at [%v]", keyStorePath)
	}

	return New(256, "SHA2", ks)
}

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// at security level 256, hash family SHA2 and using the passed KeyStore.
func NewDefaultSecurityLevelWithKeystore(keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	return New(256, "SHA2", keyStore)
}

// New 实例化 返回支持国密算法的 bccsp.BCCSP
func New(securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {

	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(securityLevel, hashFamily)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing configuration at [%v,%v]", securityLevel, hashFamily)
	}

	// Check KeyStore
	if keyStore == nil {
		return nil, errors.Errorf("Invalid bccsp.KeyStore instance. It must be different from nil.")
	}

	// Set the encryptors
	encryptors := make(map[reflect.Type]Encryptor)
	// sm4 加密选项，要注意，这里实现的sm4加密只是分组加密，没有对明文做分组操作。
	encryptors[reflect.TypeOf(&gmsm4Key{})] = &gmsm4Encryptor{}

	// Set the decryptors
	decryptors := make(map[reflect.Type]Decryptor)
	// sm4 解密选项，要注意，这里实现的sm4解密只是分组解密，没有对密文做分组操作。
	decryptors[reflect.TypeOf(&gmsm4Key{})] = &gmsm4Decryptor{}

	// Set the signers
	signers := make(map[reflect.Type]Signer)
	//sm2 国密签名
	signers[reflect.TypeOf(&gmsm2PrivateKey{})] = &gmsm2Signer{}
	// ecdsa签名，注意内部逻辑改为了sm2签名，但要注意椭圆曲线的选择是不是 sm2P256
	signers[reflect.TypeOf(&ecdsaPrivateKey{})] = &ecdsaPrivateKeySigner{}

	// Set the verifiers
	verifiers := make(map[reflect.Type]Verifier)
	//sm2 私钥验签，注意，实际上还是公钥验签
	verifiers[reflect.TypeOf(&gmsm2PrivateKey{})] = &gmsm2PrivateKeyVerifier{}
	//sm2 公钥验签
	verifiers[reflect.TypeOf(&gmsm2PublicKey{})] = &gmsm2PublicKeyKeyVerifier{}
	// ecdsa验签，注意内部逻辑改为了sm2验签，但要注意椭圆曲线的选择是不是 sm2P256
	verifiers[reflect.TypeOf(&ecdsaPrivateKey{})] = &ecdsaPrivateKeyVerifier{}
	verifiers[reflect.TypeOf(&ecdsaPublicKey{})] = &ecdsaPublicKeyKeyVerifier{}

	// Set the hashers
	hashers := make(map[reflect.Type]Hasher)
	hashers[reflect.TypeOf(&bccsp.SHAOpts{})] = &hasher{hash: conf.hashFunction}
	//sm3 Hash选项
	hashers[reflect.TypeOf(&bccsp.SM3Opts{})] = &hasher{hash: sm3.New}
	hashers[reflect.TypeOf(&bccsp.SHA256Opts{})] = &hasher{hash: sha256.New}
	hashers[reflect.TypeOf(&bccsp.SHA384Opts{})] = &hasher{hash: sha512.New384}
	hashers[reflect.TypeOf(&bccsp.SHA3_256Opts{})] = &hasher{hash: sha3.New256}
	hashers[reflect.TypeOf(&bccsp.SHA3_384Opts{})] = &hasher{hash: sha3.New384}

	impl := &impl{
		conf:       conf,
		ks:         keyStore,
		encryptors: encryptors,
		decryptors: decryptors,
		signers:    signers,
		verifiers:  verifiers,
		hashers:    hashers}

	// Set the key generators
	keyGenerators := make(map[reflect.Type]KeyGenerator)
	// sm2密钥对生成器
	keyGenerators[reflect.TypeOf(&bccsp.SM2KeyGenOpts{})] = &gmsm2KeyGenerator{}
	// sm4密钥生成器
	keyGenerators[reflect.TypeOf(&bccsp.SM4KeyGenOpts{})] = &gmsm4KeyGenerator{length: 32}
	// 注意只有国密sm2与sm4的密钥生成器
	// TODO 这里有问题:
	// 既然在前面的签名与验签处添加了内部转为sm2签名/验签的ecdsa签名/验签，
	// 那么这里也应该添加内部参数为sm2参数的ecdsa密钥对生成器:
	// ecdsa密钥生成器
	// keyGenerators[reflect.TypeOf(&bccsp.ECDSAKeyGenOpts{})] = &gmecdsaKeyGenerator{}
	impl.keyGenerators = keyGenerators

	// Set the key derivers
	keyDerivers := make(map[reflect.Type]KeyDeriver)
	// 空的keyDerivers TODO 那么为啥不直接干掉 `bccsp/gm/keyderiv.go`呢？
	impl.keyDerivers = keyDerivers

	// Set the key importers
	keyImporters := make(map[reflect.Type]KeyImporter)
	// 导入在 `bccsp/gm/keyimport.go`中定义的系列keyimporter
	keyImporters[reflect.TypeOf(&bccsp.SM4ImportKeyOpts{})] = &gmsm4ImportKeyOptsKeyImporter{}
	keyImporters[reflect.TypeOf(&bccsp.SM2PrivateKeyImportOpts{})] = &gmsm2PrivateKeyImportOptsKeyImporter{}
	keyImporters[reflect.TypeOf(&bccsp.SM2PublicKeyImportOpts{})] = &gmsm2PublicKeyImportOptsKeyImporter{}
	keyImporters[reflect.TypeOf(&bccsp.X509PublicKeyImportOpts{})] = &x509PublicKeyImportOptsKeyImporter{bccsp: impl}
	keyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})] = &ecdsaGoPublicKeyImportOptsKeyImporter{}
	keyImporters[reflect.TypeOf(&bccsp.ECDSAPrivateKeyImportOpts{})] = &ecdsaPrivateKeyImportOptsKeyImporter{}
	keyImporters[reflect.TypeOf(&bccsp.ECDSAPKIXPublicKeyImportOpts{})] = &ecdsaPKIXPublicKeyImportOptsKeyImporter{}

	impl.keyImporters = keyImporters
	return impl, nil
}

// 定义国密算法结构体 impl
type impl struct {
	conf          *config                    //bccsp实例的配置
	ks            bccsp.KeyStore             //key存储系统对象，存储和获取Key对象
	encryptors    map[reflect.Type]Encryptor //加密者映射
	decryptors    map[reflect.Type]Decryptor //解密者映射
	signers       map[reflect.Type]Signer    //签名者映射，Key实现的类型作为映射的键
	verifiers     map[reflect.Type]Verifier  //鉴定者映射，Key实现的类型作为映射的键
	hashers       map[reflect.Type]Hasher    //哈希者映射
	keyGenerators map[reflect.Type]KeyGenerator
	keyDerivers   map[reflect.Type]KeyDeriver
	keyImporters  map[reflect.Type]KeyImporter
}

// 为 impl 实现 bccsp.BCCSP 接口

func (csp *impl) ShowAlgorithms() string {
	return "sm2-sm3-sm4;"
}

// 实现KeyGen方法，生成密钥
func (csp *impl) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil.")
	}
	// 根据具体的 bccsp.KeyGenOpts 获取对应的 keyGenerator
	keyGenerator, found := csp.keyGenerators[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'KeyGenOpts' provided [%v]", opts)
	}

	k, err = keyGenerator.KeyGen(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed generating key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing key [%s]", opts.Algorithm())
		}
	}

	return k, nil
}

// 实现KeyDeriv方法，生成密钥
func (csp *impl) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	keyDeriver, found := csp.keyDerivers[reflect.TypeOf(k)]
	if !found {
		return nil, errors.Errorf("Unsupported 'Key' provided [%v]", k)
	}

	k, err = keyDeriver.KeyDeriv(k, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed deriving key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing key [%s]", opts.Algorithm())
		}
	}

	return k, nil
}

// 实现KeyImport方法，导入密钥
func (csp *impl) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	keyImporter, found := csp.keyImporters[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'KeyImportOpts' provided [%v]", opts)
	}

	k, err = keyImporter.KeyImport(raw, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed importing key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing imported key with opts [%v]", opts)
		}
	}

	return
}

// 实现GetKey方法，根据SKI读取存储起来的密钥
func (csp *impl) GetKey(ski []byte) (k bccsp.Key, err error) {
	k, err = csp.ks.GetKey(ski)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed getting key for SKI [%v]", ski)
	}

	return
}

// 实现Hash方法，对消息进行散列
func (csp *impl) Hash(msg []byte, opts bccsp.HashOpts) (digest []byte, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	hasher, found := csp.hashers[reflect.TypeOf(opts)]
	//TODO
	/*fmt.Printf("hasher----,%v", hasher)*/
	/*fmt.Printf("reflect.TypeOf(opts)----,%v", reflect.TypeOf(opts))*/
	if !found {
		return nil, errors.Errorf("Unsupported 'HashOpt' provided [%v]", opts)
	}

	digest, err = hasher.Hash(msg, opts)
	/*fmt.Printf("msg====,%v", msg)
	fmt.Printf("digest====,%v", digest)*/
	if err != nil {
		return nil, errors.Wrapf(err, "Failed hashing with opts [%v]", opts)
	}

	return
}

// 实现GetHash方法，获取hash.Hash实例
func (csp *impl) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	hasher, found := csp.hashers[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'HashOpt' provided [%v]", opts)
	}

	h, err = hasher.GetHash(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed getting hash function with opts [%v]", opts)
	}

	return
}

// 根据签名者选项opts，使用k对digest进行签名，注意如果需要对一个特别大的消息的hash值
// 进行签名，调用者则负责对该特别大的消息进行hash后将其作为digest传入
// 实现Sign方法，进行签名
func (csp *impl) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty.")
	}

	signer, found := csp.signers[reflect.TypeOf(k)]
	if !found {
		return nil, errors.Errorf("Unsupported 'SignKey' provided [%s]", k)
	}

	signature, err = signer.Sign(k, digest, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed signing with opts [%v]", opts)
	}

	return
}

// 根据鉴定者选项opts，通过对比k和digest，鉴定签名
// 实现Verify方法，进行验签
func (csp *impl) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("Invalid Key. It must not be nil.")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty.")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty.")
	}

	verifier, found := csp.verifiers[reflect.TypeOf(k)]
	if !found {
		return false, errors.Errorf("Unsupported 'VerifyKey' provided [%v]", k)
	}

	valid, err = verifier.Verify(k, signature, digest, opts)
	if err != nil {
		return false, errors.Wrapf(err, "Failed verifing with opts [%v]", opts)
	}

	return
}

// 根据加密者选项opts，使用k加密plaintext
// 实现Encrypt方法，对plaintext进行加密
// 注意，对应的sm4的encryptor实现的方法里只做了分组加密，即，没有对明文分组。
func (csp *impl) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}

	encryptor, found := csp.encryptors[reflect.TypeOf(k)]
	if !found {
		return nil, errors.Errorf("Unsupported 'EncryptKey' provided [%v]", k)
	}

	return encryptor.Encrypt(k, plaintext, opts)
}

// 根据解密者选项opts，使用k对ciphertext进行解密
// 实现Decrypt方法，对ciphertext进行解密
// 注意，对应的sm4的decryptor实现的方法里只做了分组解密，即，没有对密文分组。
func (csp *impl) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}

	decryptor, found := csp.decryptors[reflect.TypeOf(k)]
	if !found {
		return nil, errors.Errorf("Unsupported 'DecryptKey' provided [%v]", k)
	}

	plaintext, err = decryptor.Decrypt(k, ciphertext, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed decrypting with opts [%v]", opts)
	}

	return
}
