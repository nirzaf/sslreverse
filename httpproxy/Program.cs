using LowLevelDesign.Concerto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;
using Titanium.Web.Proxy.Network;

namespace httpproxy
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: httpproxy {root-cert.pem}");
            }

            using var concertoCerts = new ConcertoCertificateCache(args[0]);
            var proxyServer = new ProxyServer(userTrustRootCertificate: false);

            proxyServer.CheckCertificateRevocation = X509RevocationMode.NoCheck;
            proxyServer.CertificateManager.SaveFakeCertificates = true;
            proxyServer.CertificateManager.CertificateStorage = concertoCerts;

            Task beforeRequest(object _, SessionEventArgs ev)
            {
                return OnBeforeRequest(concertoCerts, ev);
            }

            proxyServer.OnServerConnectionCreate += OnConnect;
            proxyServer.BeforeRequest += beforeRequest;
            proxyServer.BeforeResponse += OnBeforeResponse;
            proxyServer.AfterResponse += OnAfterResponse;
            proxyServer.ServerCertificateValidationCallback += OnServerCertificateValidation;

            var httpProxy = new ExplicitProxyEndPoint(IPAddress.Loopback, 8080, true);

            proxyServer.AddEndPoint(httpProxy);
            proxyServer.Start();

            foreach (var endPoint in proxyServer.ProxyEndPoints)
                Console.WriteLine("Listening on '{0}' endpoint at Ip {1} and port: {2} ",
                    endPoint.GetType().Name, endPoint.IpAddress, endPoint.Port);

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, ev) => {
                ev.Cancel = true;
                cts.Cancel();
            };

            cts.Token.WaitHandle.WaitOne();

            // Unsubscribe & Quit
            proxyServer.OnServerConnectionCreate -= OnConnect;
            proxyServer.BeforeRequest -= beforeRequest;
            proxyServer.BeforeResponse -= OnBeforeResponse;
            proxyServer.AfterResponse -= OnAfterResponse;
            proxyServer.ServerCertificateValidationCallback -= OnServerCertificateValidation;

            proxyServer.Stop();
        }

        private static Task OnServerCertificateValidation(object sender, CertificateValidationEventArgs e)
        {
            if (e.SslPolicyErrors == SslPolicyErrors.None)
            {
                e.IsValid = true;
            }

            return Task.CompletedTask;
        }

        // Define other methods and classes here

        static Task OnConnect(object sender, Socket e)
        {
            Console.WriteLine($"Connect: {e.LocalEndPoint} -> {e.RemoteEndPoint}");

            return Task.CompletedTask;
        }

        static Task OnBeforeRequest(ConcertoCertificateCache certs, SessionEventArgs ev)
        {
            // Before the request to the remote server
            var request = ev.HttpClient.Request;
            if (!ev.IsHttps && request.Host == "titanium")
            {
                if (request.RequestUri.AbsolutePath.Equals("/cert/pem", StringComparison.OrdinalIgnoreCase))
                {
                    // send the certificate
                    var headers = new Dictionary<string, HttpHeader>() {
                        ["Content-Type"] = new HttpHeader("Content-Type", "application/x-x509-ca-cert"),
                        ["Content-Disposition"] = new HttpHeader("Content-Disposition", "inline; filename=titanium-ca-cert.pem")
                    };
                    ev.Ok(File.ReadAllBytes(certs.RootCertPath), headers, true);
                }
                else
                {
                    var headers = new Dictionary<string, HttpHeader>() {
                        ["Content-Type"] = new HttpHeader("Content-Type", "text/html"),
                    };
                    ev.Ok("<html><body><h1><a href=\"/cert/pem\">PEM</a></h1></body></html>", headers, true);
                }
            }

            return Task.CompletedTask;
        }

        static async Task OnBeforeResponse(object sender, SessionEventArgs ev)
        {
            // Before the response from the remote server is sent to the 
            // local client. You may read body here: ev.GetRequestBody()

            var request = ev.HttpClient.Request;
            var response = ev.HttpClient.Response;

            Console.WriteLine($"## REQ: {request.Url}");
            Console.WriteLine(request.HeaderText);
            if (request.HasBody)
            {
                Console.WriteLine(await ev.GetRequestBodyAsString());
            }
            Console.WriteLine(response.HeaderText);
            try
            {
                if (response.HasBody)
                {
                    var resp = (await ev.GetResponseBodyAsString());
                    Console.WriteLine($"RESP to: {request.RequestUri}");
                    Console.WriteLine(resp);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR {request.RequestUri}: {ex}");
            }
            await Task.CompletedTask;
        }

        static async Task OnAfterResponse(object sender, SessionEventArgs ev)
        {
            // After the response from the remote server was sent to the 
            // local client
            await Task.CompletedTask;
        }
    }

    internal sealed class ConcertoCertificateCache : ICertificateCache, IDisposable
    {
        private readonly string rootCertPath;

        private readonly Dictionary<string, X509Certificate2> cache = new();


        private readonly CertificateChainWithPrivateKey rootCert;

        public ConcertoCertificateCache(string rootCertPath)
        {
            this.rootCertPath = rootCertPath;
            if (File.Exists(rootCertPath))
            {
                rootCert = CertificateFileStore.LoadCertificate(rootCertPath);
            }
            else
            {
                rootCert = CertificateCreator.CreateCACertificate(name: "Titanium");
                CertificateFileStore.SaveCertificate(rootCert, rootCertPath);
            }
            cache.Add("Root", ConvertConcertoCertToWindows(rootCert));
        }

        public CertificateChainWithPrivateKey RootCert => rootCert;

        public string RootCertPath => rootCertPath;

        public X509Certificate2 LoadCertificate(string subjectName, X509KeyStorageFlags storageFlags)
        {
            lock (cache) {
                Console.WriteLine($"Loading cert for {subjectName}");
                if (!cache.TryGetValue(subjectName, out var cert))
                {
                    subjectName = subjectName.Replace("$x$", "*");
                    cert = ConvertConcertoCertToWindows(CertificateCreator.CreateCertificate(new[] { subjectName }, rootCert));
                    cache.Add(subjectName, cert);
                }
                return cert;
            }
        }

        public X509Certificate2 LoadRootCertificate(string pathOrName, string password, X509KeyStorageFlags storageFlags)
        {
            return cache["Root"];
        }

        private static X509Certificate2 ConvertConcertoCertToWindows(CertificateChainWithPrivateKey certificateChain)
        {
            const string password = "password";
            var store = new Pkcs12Store();

            var rootCert = certificateChain.PrimaryCertificate;
            var entry = new X509CertificateEntry(rootCert);
            store.SetCertificateEntry(rootCert.SubjectDN.ToString(), entry);

            var keyEntry = new AsymmetricKeyEntry(certificateChain.PrivateKey);
            store.SetKeyEntry(rootCert.SubjectDN.ToString(), keyEntry, new[] { entry });

            using var ms = new MemoryStream();
            store.Save(ms, password.ToCharArray(), new SecureRandom());

            return new X509Certificate2(ms.ToArray(), password, X509KeyStorageFlags.Exportable);
        }

        public void SaveCertificate(string subjectName, X509Certificate2 certificate)
        {
            // we are not implementing it on purpose
        }

        public void SaveRootCertificate(string pathOrName, string password, X509Certificate2 certificate)
        {
            // we are not implementing it on purpose
        }

        public void Clear()
        {
            // we are not implementing it on purpose
        }

        public void Dispose()
        {
            foreach (var c in cache.Values) { c.Dispose(); }
        }
    }
}
