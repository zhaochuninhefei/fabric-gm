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
	"reflect"
	"testing"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
)

func Test_smPublicKeyKeyDeriver_KeyDeriv(t *testing.T) {
	type args struct {
		k    bccsp.Key
		opts bccsp.KeyDerivOpts
	}
	tests := []struct {
		name    string
		kd      *smPublicKeyKeyDeriver
		args    args
		wantDk  bccsp.Key
		wantErr bool
	}{
		// Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kd := &smPublicKeyKeyDeriver{}
			gotDk, err := kd.KeyDeriv(tt.args.k, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("smPublicKeyKeyDeriver.KeyDeriv() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotDk, tt.wantDk) {
				t.Errorf("smPublicKeyKeyDeriver.KeyDeriv() = %v, want %v", gotDk, tt.wantDk)
			}
		})
	}
}
