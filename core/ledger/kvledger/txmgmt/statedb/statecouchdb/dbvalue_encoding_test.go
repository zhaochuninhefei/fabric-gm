/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statecouchdb

import (
	"fmt"
	"testing"

	"gitee.com/zhaochuninhefei/fabric-gm/core/ledger/internal/version"
	"gitee.com/zhaochuninhefei/fabric-gm/core/ledger/kvledger/txmgmt/statedb"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeOfVersionAndMetadata(t *testing.T) {
	testdata := []*statedb.VersionedValue{
		{
			Version: version.NewHeight(1, 2),
		},
		{
			Version: version.NewHeight(50, 50),
		},
		{
			Version:  version.NewHeight(50, 50),
			Metadata: []byte("sample-metadata"),
		},
	}

	for i, testdatum := range testdata {
		t.Run(fmt.Sprintf("testcase-newfmt-%d", i),
			func(t *testing.T) { testEncodeDecodeOfVersionAndMetadata(t, testdatum) },
		)
	}
}

func testEncodeDecodeOfVersionAndMetadata(t *testing.T, v *statedb.VersionedValue) {
	encodedVerField, err := encodeVersionAndMetadata(v.Version, v.Metadata)
	require.NoError(t, err)

	ver, metadata, err := decodeVersionAndMetadata(encodedVerField)
	require.NoError(t, err)
	require.Equal(t, v.Version, ver)
	require.Equal(t, v.Metadata, metadata)
}

func TestEncodeDecodeOfValueVersionMetadata(t *testing.T) {
	val := &ValueVersionMetadata{Value: []byte("val1"), VersionAndMetadata: []byte("metadata1")}
	encodedVal, err := encodeValueVersionMetadata([]byte("val1"), []byte("metadata1"))
	require.NoError(t, err)
	decodedVal, err := decodeValueVersionMetadata(encodedVal)
	require.NoError(t, err)
	require.Equal(t, val, decodedVal)
}
