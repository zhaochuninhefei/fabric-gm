/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package nwo

import (
	"fmt"
	"io/ioutil"

	http "gitee.com/zhaochuninhefei/gmgo/gmhttp"

	"gitee.com/zhaochuninhefei/fabric-gm/integration/runner"
	. "github.com/onsi/gomega"
)

type Components struct {
	ServerAddress string `json:"server_address"`
}

func (c *Components) ConfigTxGen() string {
	return c.Build("gitee.com/zhaochuninhefei/fabric-gm/cmd/configtxgen")
}

func (c *Components) Cryptogen() string {
	return c.Build("gitee.com/zhaochuninhefei/fabric-gm/cmd/cryptogen")
}

func (c *Components) Discover() string {
	return c.Build("gitee.com/zhaochuninhefei/fabric-gm/cmd/discover")
}

func (c *Components) Idemixgen() string {
	return c.Build("gitee.com/zhaochuninhefei/fabric-gm/cmd/idemixgen")
}

func (c *Components) Orderer() string {
	return c.Build("gitee.com/zhaochuninhefei/fabric-gm/cmd/orderer")
}

func (c *Components) Peer() string {
	return c.Build("gitee.com/zhaochuninhefei/fabric-gm/cmd/peer")
}

func (c *Components) Cleanup() {}

func (c *Components) Build(path string) string {
	Expect(c.ServerAddress).NotTo(BeEmpty(), "build server address is empty")

	resp, err := http.Get(fmt.Sprintf("http://%s/%s", c.ServerAddress, path))
	Expect(err).NotTo(HaveOccurred())

	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())

	if resp.StatusCode != http.StatusOK {
		Expect(resp.StatusCode).To(Equal(http.StatusOK), fmt.Sprintf("%s", body))
	}

	return string(body)
}

const CCEnvDefaultImage = "hyperledger/fabric-ccenv:latest"

var RequiredImages = []string{
	CCEnvDefaultImage,
	runner.CouchDBDefaultImage,
	runner.KafkaDefaultImage,
	runner.ZooKeeperDefaultImage,
}
