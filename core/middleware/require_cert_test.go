/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package middleware_test

// http "gitee.com/zhaochuninhefei/gmgo/gmhttp"只支持tls和x509，不支持gmtls和gmx509
import (
	"gitee.com/zhaochuninhefei/fabric-gm/core/middleware"
	"gitee.com/zhaochuninhefei/fabric-gm/core/middleware/fakes"
	http "gitee.com/zhaochuninhefei/gmgo/gmhttp"
	"gitee.com/zhaochuninhefei/gmgo/gmhttp/httptest"
	"gitee.com/zhaochuninhefei/gmgo/x509"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("RequireCert", func() {
	var (
		requireCert middleware.Middleware
		handler     *fakes.HTTPHandler
		chain       http.Handler

		req  *http.Request
		resp *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		handler = &fakes.HTTPHandler{}
		requireCert = middleware.RequireCert()
		chain = requireCert(handler)

		req = httptest.NewRequest("GET", "https:///", nil)
		req.TLS.VerifiedChains = [][]*x509.Certificate{{
			&x509.Certificate{},
		}}
		resp = httptest.NewRecorder()
	})

	It("delegates to the next handler when the first verified chain is not empty", func() {
		chain.ServeHTTP(resp, req)
		Expect(resp.Result().StatusCode).To(Equal(http.StatusOK))
		Expect(handler.ServeHTTPCallCount()).To(Equal(1))
	})

	Context("when the TLS connection state is nil", func() {
		BeforeEach(func() {
			req.TLS = nil
		})

		It("responds with http.StatusUnauthorized", func() {
			chain.ServeHTTP(resp, req)
			Expect(resp.Result().StatusCode).To(Equal(http.StatusUnauthorized))
		})

		It("does not call the next handler", func() {
			chain.ServeHTTP(resp, req)
			Expect(handler.ServeHTTPCallCount()).To(Equal(0))
		})
	})

	Context("when verified chains is nil", func() {
		BeforeEach(func() {
			req.TLS.VerifiedChains = nil
		})

		It("responds with http.StatusUnauthorized", func() {
			chain.ServeHTTP(resp, req)
			Expect(resp.Result().StatusCode).To(Equal(http.StatusUnauthorized))
		})

		It("does not call the next handler", func() {
			chain.ServeHTTP(resp, req)
			Expect(handler.ServeHTTPCallCount()).To(Equal(0))
		})
	})

	Context("when verified chains is empty", func() {
		BeforeEach(func() {
			req.TLS.VerifiedChains = [][]*x509.Certificate{}
		})

		It("responds with http.StatusUnauthorized", func() {
			chain.ServeHTTP(resp, req)
			Expect(resp.Result().StatusCode).To(Equal(http.StatusUnauthorized))
		})

		It("does not call the next handler", func() {
			chain.ServeHTTP(resp, req)
			Expect(handler.ServeHTTPCallCount()).To(Equal(0))
		})
	})

	Context("when the first verified chain is empty", func() {
		BeforeEach(func() {
			req.TLS.VerifiedChains = [][]*x509.Certificate{{}}
		})

		It("responds with http.StatusUnauthorized", func() {
			chain.ServeHTTP(resp, req)
			Expect(resp.Result().StatusCode).To(Equal(http.StatusUnauthorized))
		})

		It("does not call the next handler", func() {
			chain.ServeHTTP(resp, req)
			Expect(handler.ServeHTTPCallCount()).To(Equal(0))
		})
	})
})
