package e2e_test

import (
	"context"
	"fmt"
	gatewaydefaults "github.com/solo-io/gloo/projects/gateway/pkg/defaults"
	static_plugin_gloo "github.com/solo-io/gloo/projects/gloo/pkg/api/v1/options/static"
	"io"
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

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

	/**
		Test Overview:

		The purpose of this test is to confirm the behavior of the PROXY protocol listener filter:
		https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/listener_filters/proxy_protocol

		Per https://www.haproxy.org/download/1.9/doc/proxy-protocol.txt:
		"In both cases, the protocol simply consists in an easily parsable header placed
		by the connection initiator at the beginning of each connection. The protocol
		is intentionally stateless in that it does not expect the sender to wait for
		the receiver before sending the header, nor the receiver to send anything back."

		My goal was to create 2 gateway's:
			- 1 without useProxyProto enabled, acting as as the proxy which will forward requests to the other gateway
			- 1 WITH useProxyProto enabled, which will verify that the PROXY protocol header can be parsed

		Ideally this test will also verify more complex cases, like SNI and PROXY protocol used together,
		but I first wanted to get a simple case working. However, I have been unable to do so.
		Any feedback is appreciated!

	*/

	var (
		err error
		ctx            context.Context
		cancel         context.CancelFunc
		testClients    services.TestClients
		envoyInstance *services.EnvoyInstance

		// The proxyGateway is the gateway that accepts requests and forwards them to the proxyUpstream
		// The proxyUpstream proxies requests forward, writing the PROXY protocol connection bytes at the beginning of the connection
		proxyGateway *gatewayv1.Gateway
		proxyUpstream *gloov1.Upstream

		// The testGateway is the gateway that is configured with PROXY protocol support enabled
		// Requests handled by this Gateway will fail if they do not present the PROXY connection bytes
		testGateway *gatewayv1.Gateway


		testUpstream *v1helpers.TestUpstream
		//testUpstreamPort uint32
		sslProxyPort uint32


		secret *gloov1.Secret
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())
		defaults.HttpPort = services.NextBindPort()
		defaults.HttpsPort = services.NextBindPort()

		// run gloo
		ro := &services.RunOptions{
			NsToWrite: defaults.GlooSystem,
			NsToWatch: []string{"default", defaults.GlooSystem},
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

		// Start a TestUpstream that will handle requests
		testUpstream = v1helpers.NewTestHttpUpstream(ctx, envoyInstance.LocalAddr())
		//testUpstreamPort = testUpstream.Upstream.UpstreamType.(*gloov1.Upstream_Static).Static.Hosts[0].Port

		secret = &gloov1.Secret{
			Metadata: &core.Metadata{
				Name:      "secret",
				Namespace: "default",
			},
			Kind: &gloov1.Secret_Tls{
				Tls: &gloov1.TlsSecret{
					CertChain:  gloohelpers.Certificate(),
					PrivateKey: gloohelpers.PrivateKey(),
					RootCa:     gloohelpers.Certificate(),
				},
			},
		}
		_, err = testClients.SecretClient.Write(secret, clients.WriteOpts{})
		Expect(err).NotTo(HaveOccurred())
	})


	AfterEach(func() {
		cancel()
	})

	Context("Work In Progress", func() {

		BeforeEach(func() {
			upstream := testUpstream.Upstream
			_, err = testClients.UpstreamClient.Write(upstream, clients.WriteOpts{})
			Expect(err).NotTo(HaveOccurred())

			testVirtualService := getVirtualServiceToUpstream("test-vs", upstream, secret)
			_, err = testClients.VirtualServiceClient.Write(testVirtualService, clients.WriteOpts{})
			Expect(err).NotTo(HaveOccurred())

			testGateway = gatewaydefaults.DefaultGateway(defaults.GlooSystem)
			testGateway.Metadata.Name = testGateway.Metadata.Name + "-with-proxy-protocol-enabled"
			//testGateway.UseProxyProto = &wrappers.BoolValue{Value: true} TEMPORARY
			testGateway.GetHttpGateway().VirtualServices = []*core.ResourceRef{testVirtualService.Metadata.Ref()}
			_, err = testClients.GatewayClient.Write(testGateway, clients.WriteOpts{})
			Expect(err).NotTo(HaveOccurred())

			// Start an proxy that will forward requests to the testUpstream (via the testGateway) and include the PROXY protocol bytes
			sslProxyPort = v1helpers.StartSslProxyWithCustomProxyConnection(ctx, testGateway.BindPort, nil)

			proxyUpstream = &gloov1.Upstream{
				Metadata: &core.Metadata{
					Name:      "proxy-upstream",
					Namespace: "default",
				},
				UpstreamType: &gloov1.Upstream_Static{
					Static: &static_plugin_gloo.UpstreamSpec{
						Hosts: []*static_plugin_gloo.Host{
							{
								Addr: envoyInstance.LocalAddr(),
								Port: sslProxyPort,
							},
						},
					},
				},
				SslConfig: &gloov1.UpstreamSslConfig{
					SslSecrets: &gloov1.UpstreamSslConfig_SecretRef{
						SecretRef: secret.Metadata.Ref(),
					},
				},
			}
			_, err = testClients.UpstreamClient.Write(proxyUpstream, clients.WriteOpts{})
			Expect(err).NotTo(HaveOccurred())

			proxyVirtualService := getVirtualServiceToUpstream("proxy-vs", proxyUpstream, nil)
			_, err = testClients.VirtualServiceClient.Write(proxyVirtualService, clients.WriteOpts{})
			Expect(err).NotTo(HaveOccurred())

			proxyGateway = gatewaydefaults.DefaultGateway(defaults.GlooSystem)
			proxyGateway.BindPort = sslProxyPort
			proxyGateway.GetHttpGateway().VirtualServices = []*core.ResourceRef{proxyVirtualService.Metadata.Ref()}

			_, err = testClients.GatewayClient.Write(proxyGateway, clients.WriteOpts{})
			Expect(err).NotTo(HaveOccurred())
		})

		FIt("works pointing to proxy gateway", func() {
			cert := gloohelpers.Certificate()
			v1helpers.TestUpstreamReachable(proxyGateway.BindPort, testUpstream, &cert)
		})

	})

})


func getVirtualServiceToUpstream(name string, upstream *gloov1.Upstream, secret *gloov1.Secret) *gatewayv1.VirtualService {
	testVirtualService := getSimpleVirtualServiceToUpstream(name, upstream.Metadata.Ref())
	if secret != nil {
		testVirtualService.SslConfig = &gloov1.SslConfig{
			SslSecrets: &gloov1.SslConfig_SecretRef{
				SecretRef: secret.Metadata.Ref(),
			},
		}
	}

	return testVirtualService
}

func getSimpleVirtualServiceToUpstream(vsName string, upstreamRef *core.ResourceRef) *gatewayv1.VirtualService {
	return &gatewayv1.VirtualService{
		Metadata: &core.Metadata{
			Name:      vsName,
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
				}},
			},
		},
	}
}

type ProxyProtocolHeader struct {
	internetProtocol string
	clientIP string
	clientPort string
	proxyIP string
	proxyPort string
}

func NewLocalProxyProtocolHeader(clientPort, proxyPort string) *ProxyProtocolHeader {
	return &ProxyProtocolHeader{
		internetProtocol: "TCP4",
		clientIP: "127.0.0.1",
		clientPort: clientPort,
		proxyIP: "127.0.0.1",
		proxyPort: proxyPort,
	}
}

func (p *ProxyProtocolHeader) getConnectionString() string {
	return fmt.Sprintf("PROXY %s %s %s %s %s\r\n", p.internetProtocol, p.clientIP, p.proxyIP, p.clientPort, p.proxyPort)
}

func getProxyConnectionWithProxyProtocol(header *ProxyProtocolHeader) v1helpers.ProxyConnectionToPort {
	return func(ctx context.Context, conn net.Conn, port uint32) {
		defer conn.Close()
		fmt.Fprintf(GinkgoWriter, "proxing connection to to port %v\n", port)
		defer fmt.Fprintf(GinkgoWriter, "proxing connection to to port %v done\n", port)

		c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
		Expect(err).NotTo(HaveOccurred())
		defer c.Close()

		// Ensure PROXY protocol bytes are appended to beginning of connection
		_, err = c.Write([]byte(header.getConnectionString()))
		Expect(err).NotTo(HaveOccurred())

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		copythings := func(dst io.Writer, src io.Reader) {
			defer cancel()
			fmt.Fprintf(GinkgoWriter, "proxing copying started\n")
			w, err := io.Copy(dst, src)
			fmt.Fprintf(GinkgoWriter, "proxing copying return w: %v err %v\n", w, err)
		}

		go copythings(conn, c)
		go copythings(c, conn)
		<-ctx.Done()

	}
}