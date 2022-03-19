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
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/utils"
	"gitee.com/zhaochuninhefei/gmgo/sm2"
	"gitee.com/zhaochuninhefei/gmgo/sm4"
	"gitee.com/zhaochuninhefei/gmgo/x509"
)

/*
 * bccsp/gm/fileks.go 实现`bccsp.KeyStore`接口(bccsp/keystore.go)，用于key的文件存储读写功能
 */

// NewFileBasedKeyStore instantiated a file-based key store at a given position.
// The key store can be encrypted if a non-empty password is specifiec.
// It can be also be set as read only. In this case, any store operation
// will be forbidden
func NewFileBasedKeyStore(pwd []byte, path string, readOnly bool) (bccsp.KeyStore, error) {
	ks := &fileBasedKeyStore{}
	return ks, ks.Init(pwd, path, readOnly)
}

// fileBasedKeyStore is a folder-based KeyStore.
// Each key is stored in a separated file whose name contains the key's SKI
// and flags to identity the key's type. All the keys are stored in
// a folder whose path is provided at initialization time.
// The KeyStore can be initialized with a password, this password
// is used to encrypt and decrypt the files storing the keys.
// A KeyStore can be read only to avoid the overwriting of keys.
type fileBasedKeyStore struct {
	path string

	readOnly bool
	isOpen   bool

	pwd []byte

	// Sync
	m sync.Mutex
}

// Init initializes this KeyStore with a password, a path to a folder
// where the keys are stored and a read only flag.
// Each key is stored in a separated file whose name contains the key's SKI
// and flags to identity the key's type.
// If the KeyStore is initialized with a password, this password
// is used to encrypt and decrypt the files storing the keys.
// The pwd can be nil for non-encrypted KeyStores. If an encrypted
// key-store is initialized without a password, then retrieving keys from the
// KeyStore will fail.
// A KeyStore can be read only to avoid the overwriting of keys.
func (ks *fileBasedKeyStore) Init(pwd []byte, path string, readOnly bool) error {
	// Validate inputs
	// pwd can be nil

	if len(path) == 0 {
		return errors.New("an invalid KeyStore path provided. Path cannot be an empty string")
	}

	ks.m.Lock()
	defer ks.m.Unlock()

	if ks.isOpen {
		return errors.New("keyStore already initilized")
	}
	ks.path = path
	ks.pwd = utils.Clone(pwd)
	// 创建keystore目录
	err := ks.createKeyStoreIfNotExists()
	if err != nil {
		return err
	}

	err = ks.openKeyStore()
	if err != nil {
		return err
	}

	ks.readOnly = readOnly

	return nil
}

// ReadOnly returns true if this KeyStore is read only, false otherwise.
// If ReadOnly is true then StoreKey will fail.
func (ks *fileBasedKeyStore) ReadOnly() bool {
	return ks.readOnly
}

// GetKey returns a key object whose SKI is the one passed.
// 根据ski读取密钥或公私钥，ski作为别名alias使用
func (ks *fileBasedKeyStore) GetKey(ski []byte) (k bccsp.Key, err error) {
	// Validate arguments
	if len(ski) == 0 {
		return nil, errors.New("invalid SKI. Cannot be of zero length")
	}
	alias := hex.EncodeToString(ski)
	// 根据ski的16进制字符串获取后缀
	suffix := ks.getSuffix(alias)
	/*logger.Infof("ka.path---+++---+++%s",ks.path)
	logger.Infof("suffix---+++---+++%s",suffix)*/
	switch suffix {
	case "key":
		// 读取sm4密钥
		key, err := ks.loadKey(alias)
		if err != nil {
			return nil, fmt.Errorf("failed loading key [%x] [%s]", ski, err)
		}

		return &gmsm4Key{key, false}, nil
	case "sk":
		// 读取sm2私钥
		key, err := ks.loadPrivateKey(alias)
		if err != nil {
			return nil, fmt.Errorf("failed loading secret key [%x] [%s]", ski, err)
		}

		switch key := key.(type) {
		case *sm2.PrivateKey:
			return &gmsm2PrivateKey{key}, nil
		default:
			return nil, errors.New("secret key type not recognized")
		}
	case "pk":
		// 读取sm2公钥
		key, err := ks.loadPublicKey(hex.EncodeToString(ski))
		if err != nil {
			return nil, fmt.Errorf("failed loading public key [%x] [%s]", ski, err)
		}

		switch key := key.(type) {
		case *sm2.PublicKey:
			return &gmsm2PublicKey{key}, nil
		default:
			return nil, errors.New("public key type not recognized")
		}
	default:
		return ks.searchKeystoreForSKI(ski)
	}
}

// StoreKey stores the key k in this KeyStore.
// If this KeyStore is read only then the method will fail.
// 将密钥/公私钥存入keystore
func (ks *fileBasedKeyStore) StoreKey(k bccsp.Key) (err error) {
	if ks.readOnly {
		return errors.New("read only KeyStore")
	}

	if k == nil {
		return errors.New("invalid key. It must be different from nil")
	}
	switch k := k.(type) {
	case *gmsm2PrivateKey:
		// kk := k.(*gmsm2PrivateKey)
		err = ks.storePrivateKey(hex.EncodeToString(k.SKI()), k.privKey)
		if err != nil {
			return fmt.Errorf("failed storing SM2 private key [%s]", err)
		}
	case *gmsm2PublicKey:
		// kk := k.(*gmsm2PublicKey)
		err = ks.storePublicKey(hex.EncodeToString(k.SKI()), k.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing SM2 public key [%s]", err)
		}
	case *gmsm4Key:
		// kk := k.(*gmsm4Key)
		// keypath := ks.getPathForAlias(hex.EncodeToString(k.SKI()), "key")
		err = ks.storeKey(hex.EncodeToString(k.SKI()), k.privKey)
		if err != nil {
			return fmt.Errorf("failed storing SM4 key [%s]", err)
		}
	default:
		return fmt.Errorf("key type not reconigned [%s]", k)
	}

	return
}

// 根据ski查找key，仅在alias找不到对应后缀目录时使用。
// 默认直接存储在path目录下，遍历path下的直接子文件，按照sm2私钥读取，并比较ski是否匹配。
func (ks *fileBasedKeyStore) searchKeystoreForSKI(ski []byte) (k bccsp.Key, err error) {

	files, _ := ioutil.ReadDir(ks.path)
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		raw, err := ioutil.ReadFile(filepath.Join(ks.path, f.Name()))
		if err != nil {
			continue
		}
		// 直接按sm2私钥读取？
		key, err := x509.ReadPrivateKeyFromMem(raw, nil)
		// key, err = utils.PEMtoPrivateKey(raw, ks.pwd)
		if err != nil {
			continue
		}

		k = &gmsm2PrivateKey{key}

		if !bytes.Equal(k.SKI(), ski) {
			continue
		}

		return k, nil
	}
	return nil, errors.New("key type not recognized")
}

// 根据alias获取对应的后缀
func (ks *fileBasedKeyStore) getSuffix(alias string) string {
	// 读取到path下的存储子目录
	files, _ := ioutil.ReadDir(ks.path)
	for _, f := range files {
		// alias作为前缀过滤
		if strings.HasPrefix(f.Name(), alias) {
			// 获取子目录名的后缀
			if strings.HasSuffix(f.Name(), "sk") {
				// 私钥
				return "sk"
			}
			if strings.HasSuffix(f.Name(), "pk") {
				// 公钥
				return "pk"
			}
			if strings.HasSuffix(f.Name(), "key") {
				// sm4密钥
				return "key"
			}
			break
		}
	}
	return ""
}

// 存储私钥，后缀sk
func (ks *fileBasedKeyStore) storePrivateKey(alias string, privateKey interface{}) error {
	// 将私钥转为pem字节流
	rawKey, err := utils.PrivateKeyToPEM(privateKey, ks.pwd)
	if err != nil {
		logger.Errorf("Failed converting private key to PEM [%s]: [%s]", alias, err)
		return err
	}
	// 写入keystore存储目录 ${path}/${alias}_sk
	err = ioutil.WriteFile(ks.getPathForAlias(alias, "sk"), rawKey, 0700)
	if err != nil {
		logger.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

// 存储公钥，后缀pk
func (ks *fileBasedKeyStore) storePublicKey(alias string, publicKey interface{}) error {
	// 将公钥转为pem字节流
	rawKey, err := utils.PublicKeyToPEM(publicKey, ks.pwd)
	if err != nil {
		logger.Errorf("Failed converting public key to PEM [%s]: [%s]", alias, err)
		return err
	}
	// 写入keystore存储目录 ${path}/${alias}_pk
	err = ioutil.WriteFile(ks.getPathForAlias(alias, "pk"), rawKey, 0700)
	if err != nil {
		logger.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

// 存储密钥，后缀key
func (ks *fileBasedKeyStore) storeKey(alias string, key []byte) error {
	//pem, err := utils.AEStoEncryptedPEM(key, ks.pwd)

	if len(ks.pwd) == 0 {
		ks.pwd = nil
	}
	// sm4密钥转为pem字节流
	pem, err := sm4.WriteKeytoMem(key, ks.pwd)
	if err != nil {
		logger.Errorf("Failed converting key to PEM [%s]: [%s]", alias, err)
		return err
	}
	// 写入keystore存储目录 ${path}/${alias}_key
	err = ioutil.WriteFile(ks.getPathForAlias(alias, "key"), pem, 0700)
	if err != nil {
		logger.Errorf("Failed storing key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

// 读取sm2私钥
func (ks *fileBasedKeyStore) loadPrivateKey(alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, "sk")
	logger.Infof("loadPrivateKey : %s", path)
	logger.Debugf("Loading private key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	// 将pem字节流转为sm2私钥
	// privateKey, err := utils.PEMtoPrivateKey(raw, ks.pwd)
	privateKey, err := x509.ReadPrivateKeyFromMem(raw, nil)
	if err != nil {
		logger.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	return privateKey, nil
}

// 读取sm2公钥
func (ks *fileBasedKeyStore) loadPublicKey(alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, "pk")
	logger.Debugf("Loading public key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading public key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	// privateKey, err := utils.PEMtoPublicKey(raw, ks.pwd)
	privateKey, err := x509.ReadPublicKeyFromMem(raw, nil)
	if err != nil {
		logger.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	return privateKey, nil
}

// 读取sm4密钥
func (ks *fileBasedKeyStore) loadKey(alias string) ([]byte, error) {
	path := ks.getPathForAlias(alias, "key")
	logger.Infof("loadKey : %s", path)
	logger.Debugf("Loading key [%s] at [%s]...", alias, path)

	pem, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	//key, err := utils.PEMtoAES(pem, ks.pwd)
	if len(ks.pwd) == 0 {
		ks.pwd = nil
	}
	key, err := sm4.ReadKeyFromMem(pem, ks.pwd)
	if err != nil {
		logger.Errorf("Failed parsing key [%s]: [%s]", alias, err)

		return nil, err
	}

	return key, nil
}

// keystore目录不存在时创建
func (ks *fileBasedKeyStore) createKeyStoreIfNotExists() error {
	// Check keystore directory
	ksPath := ks.path
	missing, err := utils.DirMissingOrEmpty(ksPath)

	if missing {
		logger.Debugf("KeyStore path [%s] missing [%t]: [%s]", ksPath, missing, utils.ErrToString(err))

		err := ks.createKeyStore()
		if err != nil {
			logger.Errorf("Failed creating KeyStore At [%s]: [%s]", ksPath, err.Error())
			return nil
		}
	}

	return nil
}

func (ks *fileBasedKeyStore) createKeyStore() error {
	// Create keystore directory root if it doesn't exist yet
	ksPath := ks.path
	logger.Debugf("Creating KeyStore at [%s]...", ksPath)

	os.MkdirAll(ksPath, 0755)

	logger.Debugf("KeyStore created at [%s].", ksPath)
	return nil
}

func (ks *fileBasedKeyStore) openKeyStore() error {
	if ks.isOpen {
		return nil
	}

	logger.Debugf("KeyStore opened at [%s]...done", ks.path)

	return nil
}

func (ks *fileBasedKeyStore) getPathForAlias(alias, suffix string) string {
	return filepath.Join(ks.path, alias+"_"+suffix)
}
