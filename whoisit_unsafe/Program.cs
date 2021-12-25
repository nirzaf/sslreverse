using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Whois;

namespace whois
{
    class Program
    {
        static async Task Main()
        {

            var listener = new HttpListener();
            listener.Prefixes.Add("http://+:5000/");
            listener.AuthenticationSchemes = AuthenticationSchemes.Basic;
            listener.Start();

            Console.CancelKeyPress += (o, ev) => listener.Stop();

            while (true)
            {
                var ctx = await listener.GetContextAsync();

                var req = ctx.Request;
                var resp = ctx.Response;

                Console.WriteLine($"{req.HttpMethod}: {req.RawUrl}");
                var identity = (HttpListenerBasicIdentity)ctx.User.Identity;

                if (identity.Name != "demo" || identity.Password != "Demo123;")
                {
                    resp.StatusCode = 401;
                    resp.StatusDescription = "Invalid username or password";
                }
                else if (req.HttpMethod != "POST" && req.HttpMethod != "PUT")
                {
                    resp.StatusCode = 405;
                }
                else if (req.ContentLength64 == 0)
                {
                    resp.StatusCode = 406;
                    resp.StatusDescription = "The content can't be empty";
                }
                else
                {
                    using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
                    var query = await reader.ReadToEndAsync();
                    Console.WriteLine($"Starting whois for {query}");
                    var lookup = new WhoisLookup();
                    var result = await lookup.LookupAsync(query);

                    Console.WriteLine("Whois query for {0} completed with status {1}", query, result.Status);
                    using var writer = new StreamWriter(ctx.Response.OutputStream, Encoding.UTF8);
                    writer.WriteLine(result.Content);
                }
                resp.Close();
            }
        }
    }
}
