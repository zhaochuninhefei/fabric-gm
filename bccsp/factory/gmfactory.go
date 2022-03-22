package factory

import (
	// "errors"

	"gitee.com/zhaochuninhefei/fabric-gm/bccsp"
	"gitee.com/zhaochuninhefei/fabric-gm/bccsp/sw"
	"github.com/pkg/errors"
)

/*
bccsp/factory/gmfactory.go 定义 GMFactory 结构体并为其实现`factory.BCCSPFactory`接口(bccsp/factory/factory.go)
TODO SWFactory已经支持国密，是否还有维持 GMFactory 的必要？
*/

const (
	// GuomiBasedFactoryName is the name of the factory of the software-based BCCSP implementation
	GuomiBasedFactoryName = "GM"
)

// GMFactory is the factory of the guomi-based BCCSP.
type GMFactory struct{}

// Name returns the name of this factory
func (f *GMFactory) Name() string {
	return GuomiBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *GMFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if config == nil || config.SwOpts == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	gmOpts := config.SwOpts

	var ks bccsp.KeyStore
	if gmOpts.Ephemeral {
		ks = sw.NewDummyKeyStore()
	} else if gmOpts.FileKeystore != nil {
		fks, err := sw.NewFileBasedKeyStore(nil, gmOpts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to initialize gm software key store.")
		}
		ks = fks
	} else {
		// Default to DummyKeystore
		ks = sw.NewDummyKeyStore()
	}

	return sw.NewWithParams(true, gmOpts.SecLevel, gmOpts.HashFamily, ks)
	//return gm.New(gmOpts.SecLevel, gmOpts.HashFamily, ks)
}
