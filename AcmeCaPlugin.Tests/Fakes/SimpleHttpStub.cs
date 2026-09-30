using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests.Fakes
{
    /// <summary>
    /// Minimal single-response in-process HTTP stub used for Ping() tests that need to control
    /// the raw response body/status code without simulating the full ACME protocol.
    /// </summary>
    public sealed class SimpleHttpStub : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly Task _loop;

        public string Url { get; }

        public SimpleHttpStub(string body, int statusCode = 200)
        {
            var port = GetFreePort();
            Url = $"http://127.0.0.1:{port}/directory";
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            _listener.Start();
            _loop = Task.Run(async () =>
            {
                try
                {
                    var ctx = await _listener.GetContextAsync();
                    var bytes = Encoding.UTF8.GetBytes(body);
                    ctx.Response.StatusCode = statusCode;
                    ctx.Response.ContentLength64 = bytes.Length;
                    ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
                    ctx.Response.OutputStream.Close();
                }
                catch
                {
                    // listener stopped/disposed
                }
            });
        }

        private static int GetFreePort()
        {
            var l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }

        public void Dispose()
        {
            try { _listener.Stop(); } catch { }
            try { _listener.Close(); } catch { }
        }
    }
}
