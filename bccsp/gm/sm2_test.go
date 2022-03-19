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
	"fmt"
	"reflect"
	"testing"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
	"gitee.com/zhaochuninhefei/gmgo/sm2"
)

func Test_equalSm2AndEcdsaPK(t *testing.T) {
	ecdsaKeyGen := &gmecdsaKeyGenerator{}
	k, _ := ecdsaKeyGen.KeyGen(nil)
	puk := k.(*ecdsaPrivateKey).privKey.PublicKey
	sm2pk := sm2.PublicKey{
		Curve: puk.Curve,
		X:     puk.X,
		Y:     puk.Y,
	}
	ecdsaPrivKey := k.(*ecdsaPrivateKey).privKey
	sm2privKey := sm2.PrivateKey{
		D:         ecdsaPrivKey.D,
		PublicKey: sm2pk,
	}
	fmt.Printf("ecdsaPrivKey.Curve: %v\n", ecdsaPrivKey.Curve)
	fmt.Printf("sm2privKey.Curve: %v\n", sm2privKey.Curve)
	if !reflect.DeepEqual(ecdsaPrivKey.Curve, sm2privKey.Curve) {
		t.Errorf("k与sm2privKey的曲线并不相同 k: %v, sm2privKey: %v", ecdsaPrivKey.Curve, sm2privKey.Curve)
	}
	fmt.Printf("ecdsaPrivKey.D: %v\n", ecdsaPrivKey.D)
	fmt.Printf("sm2privKey.D: %v\n", sm2privKey.D)
	if !reflect.DeepEqual(ecdsaPrivKey.D, sm2privKey.D) {
		t.Errorf("k与sm2privKey的私钥并不相同 k: %v, sm2privKey: %v", ecdsaPrivKey.D, sm2privKey.D)
	}
	fmt.Printf("ecdsaPrivKey.X: %v\n", ecdsaPrivKey.X)
	fmt.Printf("sm2privKey.X: %v\n", sm2privKey.X)
	if !reflect.DeepEqual(ecdsaPrivKey.X, sm2privKey.X) {
		t.Errorf("k与sm2privKey的公钥x座标并不相同 k: %v, sm2privKey: %v", ecdsaPrivKey.X, sm2privKey.X)
	}
	fmt.Printf("ecdsaPrivKey.Y: %v\n", ecdsaPrivKey.Y)
	fmt.Printf("sm2privKey.Y: %v\n", sm2privKey.Y)
	if !reflect.DeepEqual(ecdsaPrivKey.Y, sm2privKey.Y) {
		t.Errorf("k与sm2privKey的公钥y座标并不相同 k: %v, sm2privKey: %v", ecdsaPrivKey.Y, sm2privKey.Y)
	}
}

func Test_ecdsaPrivateKeySigner_Sign(t *testing.T) {
	type args struct {
		k      bccsp.Key
		digest []byte
		opts   bccsp.SignerOpts
	}
	tests := []struct {
		name          string
		s             *ecdsaPrivateKeySigner
		args          args
		wantSignature []byte
		wantErr       bool
	}{
		// Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &ecdsaPrivateKeySigner{}
			gotSignature, err := s.Sign(tt.args.k, tt.args.digest, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("ecdsaPrivateKeySigner.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSignature, tt.wantSignature) {
				t.Errorf("ecdsaPrivateKeySigner.Sign() = %v, want %v", gotSignature, tt.wantSignature)
			}
		})
	}
}
