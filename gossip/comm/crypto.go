/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"context"

	"gitee.com/zhaochuninhefei/fabric-gm/common/util"
	"gitee.com/zhaochuninhefei/gmgo/grpc/credentials"
	"gitee.com/zhaochuninhefei/gmgo/grpc/peer"
)

func certHashFromRawCert(rawCert []byte) []byte {
	if len(rawCert) == 0 {
		return nil
	}
	return util.ComputeSM3(rawCert)
}

// ExtractCertificateHash extracts the hash of the certificate from the stream
func extractCertificateHashFromContext(ctx context.Context) []byte {
	pr, extracted := peer.FromContext(ctx)
	if !extracted {
		return nil
	}

	authInfo := pr.AuthInfo
	if authInfo == nil {
		return nil
	}

	tlsInfo, isTLSConn := authInfo.(credentials.TLSInfo)
	if !isTLSConn {
		return nil
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	raw := certs[0].Raw
	return certHashFromRawCert(raw)
}
