package test

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/factory"
	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/sw"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestGM(t *testing.T) {
	// bccsp工厂配置(yaml)
	yamlCFG := `
BCCSP:
    default: SW
    SW:
        Hash: SHA3
        Security: 384
    UsingGM: y
`
	csp, err := readYaml2Bccsp(yamlCFG)
	if err != nil {
		t.Fatalf("读取YAML到BCCSP失败: %s", err)
	}
	fmt.Printf("csp 支持的算法: %s\n", csp.ShowAlgorithms())

	// 定义明文
	plaintext := []byte("月黑见渔灯，孤光一点萤。微微风簇浪，散作满河星。")
	fmt.Printf("明文: %s\n", plaintext)

	// 对称加密

	// 获取sm4密钥
	sm4Key, err := csp.KeyGen(&bccsp.SM4KeyGenOpts{Temporary: true})
	if err != nil {
		t.Fatalf("生成sm4Key失败: %s", err)
	}
	sm4KeyBytes, err := sm4Key.Bytes()
	if err != nil {
		t.Fatalf("获取sm4KeyBytes失败: %s", err)
	}
	fmt.Printf("sm4密钥: %s\n", hex.EncodeToString(sm4KeyBytes))
	// 获取IV
	sm4IV, err := sw.GetRandomBytes(16)
	if err != nil {
		t.Fatalf("获取sm4IV失败: %s", err)
	}
	fmt.Printf("sm4IV: %s\n", hex.EncodeToString(sm4IV))

	// sm4加密
	sm4Opts := &bccsp.SM4EncrypterOpts{
		MODE: "OFB",
		IV:   sm4IV}
	ciphertext, err := csp.Encrypt(sm4Key, plaintext, sm4Opts)
	if err != nil {
		t.Fatalf("sm4加密失败: %s", err)
	}
	fmt.Printf("密文: %s\n", hex.EncodeToString(ciphertext))
	// sm4解密
	textAfterDecrypt, err := csp.Decrypt(sm4Key, ciphertext, sm4Opts)
	if err != nil {
		t.Fatalf("sm4解密失败: %s", err)
	}
	fmt.Printf("解密后的明文: %s\n", textAfterDecrypt)
	assert.Equal(t, plaintext, textAfterDecrypt)

	// 散列
	digest1, err := csp.Hash(plaintext, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("sm3散列失败: %s", err)
	}
	fmt.Printf("sm3散列: %s\n", hex.EncodeToString(digest1))
	digest2, err := csp.Hash(textAfterDecrypt, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("sm3散列失败: %s", err)
	}
	fmt.Printf("sm3散列: %s\n", hex.EncodeToString(digest2))
	assert.Equal(t, digest1, digest2)

	// 生成sm2密钥对
	sm2Priv, err := csp.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: true})
	if err != nil {
		t.Fatalf("生成sm2密钥对失败: %s", err)
	}
	sm2Pub, _ := sm2Priv.PublicKey()
	sm2PrivBytes, _ := sm2Priv.Bytes()
	sm2PubBytes, _ := sm2Pub.Bytes()
	fmt.Printf("sm2私钥: %s\n", hex.EncodeToString(sm2PrivBytes))
	fmt.Printf("sm2公钥: %s\n", hex.EncodeToString(sm2PubBytes))

	// sm2私钥签名
	sign, err := csp.Sign(sm2Priv, plaintext, nil)
	if err != nil {
		t.Fatalf("sm2签名失败: %s", err)
	}
	fmt.Printf("sm2签名: %s\n", hex.EncodeToString(sign))
	// sm2公钥验签
	valid, err := csp.Verify(sm2Pub, sign, plaintext, nil)
	if err != nil {
		t.Fatalf("sm2公钥验签失败: %s", err)
	}
	if valid {
		fmt.Println("sm2公钥验签成功")
	}
	assert.Equal(t, true, valid)
	// sm2私钥验签
	valid2, err := csp.Verify(sm2Priv, sign, plaintext, nil)
	if err != nil {
		t.Fatalf("sm2私钥验签失败: %s", err)
	}
	if valid2 {
		fmt.Println("sm2私钥验签成功")
	}
	assert.Equal(t, true, valid2)
}

func readYaml2Bccsp(yamlCFG string) (bccsp.BCCSP, error) {
	viper.SetConfigType("yaml")
	err := viper.ReadConfig(strings.NewReader(yamlCFG))
	if err != nil {
		return nil, err
	}
	var bccspFactoryOpts *factory.FactoryOpts
	err = viper.UnmarshalKey("bccsp", &bccspFactoryOpts)
	if err != nil {
		return nil, err
	}
	csp, err := factory.GetBCCSPFromOpts(bccspFactoryOpts)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("csp 支持的算法: %s\n", csp.ShowAlgorithms())
	return csp, nil
}
