/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testdata

import "gitee.com/zhaochuninhefei/fabric-gm/common/metrics"

//gendoc:ignore

// This should be ignored by doc generation because of the directive above.

var (
	Ignored = metrics.CounterOpts{
		Namespace: "ignored",
		Name:      "ignored",
	}
)
