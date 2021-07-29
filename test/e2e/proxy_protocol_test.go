package e2e_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/solo-io/gloo/projects/gloo/pkg/api/v1/core/matchers"
	"github.com/solo-io/solo-kit/pkg/api/v1/resources"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	gatewaydefaults "github.com/solo-io/gloo/projects/gateway/pkg/defaults"

	gatewayv1 "github.com/solo-io/gloo/projects/gateway/pkg/api/v1"
	gloov1 "github.com/solo-io/gloo/projects/gloo/pkg/api/v1"
	"github.com/solo-io/gloo/projects/gloo/pkg/defaults"
	gloohelpers "github.com/solo-io/gloo/test/helpers"
	"github.com/solo-io/gloo/test/services"
	"github.com/solo-io/gloo/test/v1helpers"
	"github.com/solo-io/solo-kit/pkg/api/v1/clients"
	"github.com/solo-io/solo-kit/pkg/api/v1/resources/core"
)

var _ = Describe("Proxy Protocol", func() {

	var (
		err           error
		ctx           context.Context
		cancel        context.CancelFunc
		testClients   services.TestClients
		envoyInstance *services.EnvoyInstance

		gateway        *gatewayv1.Gateway
		virtualService *gatewayv1.VirtualService
		testUpstream   *v1helpers.TestUpstream
		secret         *gloov1.Secret
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())
		defaults.HttpPort = services.NextBindPort()
		defaults.HttpsPort = services.NextBindPort()

		// run gloo
		ro := &services.RunOptions{
			NsToWrite: defaults.GlooSystem,
			NsToWatch: []string{
				"default",
				defaults.GlooSystem,
			},
			WhatToRun: services.What{
				DisableFds: true,
				DisableUds: true,
			},
		}
		testClients = services.RunGlooGatewayUdsFds(ctx, ro)

		// run envoy
		envoyInstance, err = envoyFactory.NewEnvoyInstance()
		Expect(err).NotTo(HaveOccurred())
		err = envoyInstance.RunWithRole(defaults.GlooSystem+"~"+gatewaydefaults.GatewayProxyName, testClients.GlooPort)
		Expect(err).NotTo(HaveOccurred())

		// prepare default resources
		secret = &gloov1.Secret{
			Metadata: &core.Metadata{
				Name:      "secret",
				Namespace: "default",
			},
			Kind: &gloov1.Secret_Tls{
				Tls: &gloov1.TlsSecret{
					CertChain:  gloohelpers.Certificate(),
					PrivateKey: gloohelpers.PrivateKey(),
				},
			},
		}

		testUpstream = v1helpers.NewTestHttpUpstream(ctx, envoyInstance.LocalAddr())

		virtualService = getVirtualServiceToUpstream(testUpstream.Upstream.Metadata.Ref(), nil)

		gateway = gatewaydefaults.DefaultGateway(defaults.GlooSystem)
	})

	JustBeforeEach(func() {
		// Write Secret
		_, err = testClients.SecretClient.Write(secret, clients.WriteOpts{})
		Expect(err).NotTo(HaveOccurred())

		// Write Upstream
		_, err = testClients.UpstreamClient.Write(testUpstream.Upstream, clients.WriteOpts{})
		Expect(err).NotTo(HaveOccurred())

		// Write VirtualService
		_, err = testClients.VirtualServiceClient.Write(virtualService, clients.WriteOpts{})
		Expect(err).NotTo(HaveOccurred())

		// Write Gateway
		_, err = testClients.GatewayClient.Write(gateway, clients.WriteOpts{})
		Expect(err).NotTo(HaveOccurred())

		// Wait for a proxy to be generated
		gloohelpers.EventuallyResourceAccepted(func() (resources.InputResource, error) {
			return testClients.ProxyClient.Read(defaults.GlooSystem, gatewaydefaults.GatewayProxyName, clients.ReadOpts{})
		})
	})

	AfterEach(func() {
		cancel()
	})

	EventuallyGatewayReturnsOk := func(client *http.Client, scheme string) {
		EventuallyWithOffset(1, func() (int, error) {
			var buf bytes.Buffer
			res, err := client.Post(fmt.Sprintf("%s://%s:%d/1", scheme, "localhost", gateway.BindPort), "application/octet-stream", &buf)
			if err != nil {
				return 0, err
			}
			return res.StatusCode, nil

		}, "30s", "1s").Should(Equal(http.StatusOK))
	}

	// TEMP - just to test the plumbing
	Context("http", func() {

		const scheme = "http"

		BeforeEach(func() {
			// http gateway
			gateway = gatewaydefaults.DefaultGateway(defaults.GlooSystem)
			// vs without sslConfig
			virtualService = getVirtualServiceToUpstream(testUpstream.Upstream.Metadata.Ref(), nil)
		})

		Context("without PROXY protocol", func() {

			BeforeEach(func() {
				gateway.UseProxyProto = &wrappers.BoolValue{Value: false}
			})

			It("works", func() {
				client := getHttpClientWithoutProxyProtocol("")

				EventuallyGatewayReturnsOk(client, scheme)
			})
		})

	})

	Context("https", func() {

		const scheme = "https"

		BeforeEach(func() {
			// https gateway
			gateway = gatewaydefaults.DefaultSslGateway(defaults.GlooSystem)
			// vs with sslConfig
			virtualService = getVirtualServiceToUpstream(testUpstream.Upstream.Metadata.Ref(), secret.Metadata.Ref())
		})

		Context("without PROXY protocol", func() {

			BeforeEach(func() {
				gateway.UseProxyProto = &wrappers.BoolValue{Value: false}
			})

			It("works", func() {
				client := getHttpClientWithoutProxyProtocol(gloohelpers.Certificate())

				EventuallyGatewayReturnsOk(client, scheme)
			})
		})

		FContext("with PROXY protocol", func() {

			BeforeEach(func() {
				gateway.UseProxyProto = &wrappers.BoolValue{Value: true}
			})

			It("works", func() {
				proxyProtocolBytes := []byte("PROXY TCP4 1.2.3.4 1.2.3.5 443 443\r\n")
				client := getHttpClientWithProxyProtocol(gloohelpers.Certificate(), proxyProtocolBytes)

				EventuallyGatewayReturnsOk(client, scheme)
			})
		})

		// TODO: probably verify in the metrics that the tls inspect doesnt complain that sni not found?

	})

})

func getHttpClientWithoutProxyProtocol(rootCACert string) *http.Client {
	client, err := getHttpClient(rootCACert, nil)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return client
}

func getHttpClientWithProxyProtocol(rootCACert string, proxyProtocolBytes []byte) *http.Client {
	client, err := getHttpClient(rootCACert, proxyProtocolBytes)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return client
}

func getHttpClient(rootCACert string, proxyProtocolBytes []byte) (*http.Client, error) {
	var client http.Client

	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: true,

		// TODO - support ServerName
	}

	if rootCACert != "" {
		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM([]byte(rootCACert))
		if !ok {
			return nil, fmt.Errorf("ca cert is not OK")
		}
		tlsClientConfig.RootCAs = caCertPool
	}

	client.Transport = &http.Transport{
		TLSClientConfig: tlsClientConfig,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var zeroDialer net.Dialer
			c, err := zeroDialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if len(proxyProtocolBytes) > 0 {
				// inject proxy protocol bytes
				// example: []byte("PROXY TCP4 1.2.3.4 1.2.3.5 443 443\r\n")
				_, err = c.Write(proxyProtocolBytes)
				if err != nil {
					_ = c.Close()
					return nil, err
				}
			}

			return c, nil
		},
	}

	return &client, nil

}

func getVirtualServiceToUpstream(upstreamRef *core.ResourceRef, secretRef *core.ResourceRef) *gatewayv1.VirtualService {
	vs := &gatewayv1.VirtualService{
		Metadata: &core.Metadata{
			Name:      "vs",
			Namespace: defaults.GlooSystem,
		},
		VirtualHost: &gatewayv1.VirtualHost{
			Domains: []string{"*"},
			Routes: []*gatewayv1.Route{{
				Action: &gatewayv1.Route_RouteAction{
					RouteAction: &gloov1.RouteAction{
						Destination: &gloov1.RouteAction_Single{
							Single: &gloov1.Destination{
								DestinationType: &gloov1.Destination_Upstream{
									Upstream: upstreamRef,
								},
							},
						},
					},
				},
				Matchers: []*matchers.Matcher{
					{
						PathSpecifier: &matchers.Matcher_Prefix{
							Prefix: "/",
						},
					},
				},
			}},
		},
	}
	if secretRef != nil {
		vs.SslConfig = &gloov1.SslConfig{
			SslSecrets: &gloov1.SslConfig_SecretRef{
				SecretRef: secretRef,
			},
		}
	}
	return vs
}
