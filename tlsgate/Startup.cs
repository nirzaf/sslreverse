using System;
using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Service.Proxy;

namespace tlsgate
{
    public class Startup
    {

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpProxy();
        }

        public void Configure(IApplicationBuilder app, IHttpProxy httpProxy)
        {
            var httpClient = new HttpMessageInvoker(new SocketsHttpHandler()
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.None,
                UseCookies = false
            });

            var transformer = HttpTransformer.Default;
            var requestOptions = new RequestProxyOptions { Timeout = TimeSpan.FromSeconds(100) };

            app.UseRouting();

            app.UseEndpoints(endpoints => {
                endpoints.Map("/{**catch-all}", async httpContext =>
                {
                    await httpProxy.ProxyAsync(httpContext, "http://whoisit_unsafe:5000", httpClient, requestOptions, transformer);
                });
            });
        }
    }
}
