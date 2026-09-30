using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.Acme.Tests.Fakes
{
    /// <summary>
    /// Minimal in-process HTTP server that simulates just enough of an ACME (RFC 8555) server
    /// for AcmeClient/AcmeClientManager/AcmeCaPlugin.Enroll to be exercised end-to-end over real
    /// loopback HTTP, without any network access outside the local machine and without needing to
    /// intercept HttpMessageHandler (which the production code does not expose as an injectable
    /// seam). Handlers are keyed by absolute path suffix; every response includes a fresh
    /// Replay-Nonce header since AcmeClient fetches a nonce before every request.
    /// </summary>
    public sealed class FakeAcmeServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly Task _loop;
        private int _nonceCounter;

        public string BaseUrl { get; }
        public string DirectoryUrl => BaseUrl + "directory";

        public string OrderStatus = "ready";
        public string AuthzStatus = "valid";
        public string ChallengeType = "dns-01";
        public string ChallengeStatus = "valid";
        public bool FailNewAccount = false;
        public bool FailNewOrder = false;
        public bool FailRevoke = false;
        public bool FailGetAuthz = false;
        public bool FailAnswerChallenge = false;
        public bool FailGetOrder = false;
        /// <summary>Number of times /order/1 should fail with 500 before succeeding, used to
        /// exercise WaitForOrderStatusAsync's catch-and-continue polling branch.</summary>
        public int FailGetOrderTimes = 0;
        /// <summary>Number of times /order/1 should report an empty status before reporting the
        /// real OrderStatus, exercising WaitForOrderStatusAsync's "payload/status is null" continue
        /// branch.</summary>
        public int EmptyOrderStatusTimes = 0;
        public bool FailCertificate = false;
        public bool OmitFinalizeUrl = false;
        /// <summary>Number of times /new-order should reject the request with a badNonce error
        /// before succeeding, to exercise AcmeClient.PostWithNonceRetry's retry-on-badNonce loop.</summary>
        public int BadNonceFailuresRemaining = 0;
        /// <summary>When true, /finalize/1 reports status "valid" but with an empty certificate
        /// URL, exercising the "order valid but no certificate yet" branch in AcmeCaPlugin.Enroll.</summary>
        public bool FinalizeValidWithoutCertificate = false;
        /// <summary>When true, /finalize/1 returns an Order object with a null "status" field
        /// (rather than a null Order itself), exercising the null-conditional "unknown status"
        /// fallback branches in AcmeCaPlugin.Enroll's not-ready path.</summary>
        public bool FinalizeReturnsNullStatus = false;
        /// <summary>When set, /chal/1 always reports this status (e.g. "invalid") together with a
        /// populated error object, exercising AnswerChallengeAsync/PollChallengeStatusAsync's
        /// error-logging and max-retries-exhausted-without-exception branches.</summary>
        public string ChallengeErrorDetail = null;
        /// <summary>When true, /new-order omits the Location header, exercising OrderUrl's
        /// null-conditional fallback in AcmeClient.CreateOrderAsync.</summary>
        public bool OmitNewOrderLocationHeader = false;
        /// <summary>When true, every request to /chal/1 after the first (the initial challenge
        /// submission) fails with 500, so PollChallengeStatusAsync's catch-and-retry (and, if
        /// ChallengeStatus stays "pending" long enough, its exceeded-max-retries rethrow) can be
        /// exercised deterministically.</summary>
        public bool FailChallengePollsAfterSubmit = false;
        private int _chalRequestCount;
        public int NewAccountCallCount;
        public int NewOrderCallCount;

        public FakeAcmeServer()
        {
            var port = GetFreePort();
            BaseUrl = $"http://127.0.0.1:{port}/";
            _listener = new HttpListener();
            _listener.Prefixes.Add(BaseUrl);
            _listener.Start();
            _loop = Task.Run(AcceptLoop);
        }

        private static int GetFreePort()
        {
            var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }

        private async Task AcceptLoop()
        {
            while (!_cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await _listener.GetContextAsync();
                }
                catch
                {
                    return;
                }

                try
                {
                    await Handle(ctx);
                }
                catch
                {
                    try { ctx.Response.StatusCode = 500; ctx.Response.Close(); } catch { }
                }
            }
        }

        private async Task Handle(HttpListenerContext ctx)
        {
            var path = ctx.Request.Url.AbsolutePath;
            ctx.Response.Headers.Add("Replay-Nonce", "nonce-" + Interlocked.Increment(ref _nonceCounter));
            ctx.Response.ContentType = "application/json";

            if (path.EndsWith("/directory"))
            {
                Write(ctx, 200, $@"{{
                    ""newNonce"": ""{BaseUrl}new-nonce"",
                    ""newAccount"": ""{BaseUrl}new-acct"",
                    ""newOrder"": ""{BaseUrl}new-order"",
                    ""revokeCert"": ""{BaseUrl}revoke-cert"",
                    ""keyChange"": ""{BaseUrl}key-change""
                }}");
                return;
            }

            if (path.EndsWith("/new-nonce"))
            {
                Write(ctx, 204, "");
                return;
            }

            if (path.EndsWith("/new-acct"))
            {
                Interlocked.Increment(ref NewAccountCallCount);
                if (FailNewAccount)
                {
                    Write(ctx, 400, @"{""type"":""urn:ietf:params:acme:error:malformed"",""detail"":""bad account""}");
                    return;
                }
                ctx.Response.Headers.Add("Location", $"{BaseUrl}acct/1");
                Write(ctx, 201, @"{""status"":""valid""}");
                return;
            }

            if (path.EndsWith("/new-order"))
            {
                Interlocked.Increment(ref NewOrderCallCount);
                if (FailNewOrder)
                {
                    Write(ctx, 400, @"{""type"":""urn:ietf:params:acme:error:malformed"",""detail"":""bad order""}");
                    return;
                }
                if (BadNonceFailuresRemaining > 0)
                {
                    BadNonceFailuresRemaining--;
                    Write(ctx, 400, @"{""type"":""urn:ietf:params:acme:error:badNonce"",""detail"":""stale nonce""}");
                    return;
                }
                if (!OmitNewOrderLocationHeader)
                    ctx.Response.Headers.Add("Location", $"{BaseUrl}order/1");
                var newOrderFinalizeField = OmitFinalizeUrl ? "" : $@",""finalize"": ""{BaseUrl}finalize/1""";
                Write(ctx, 201, $@"{{
                    ""status"": ""{OrderStatus}"",
                    ""authorizations"": [""{BaseUrl}authz/1""]{newOrderFinalizeField}
                }}");
                return;
            }

            if (path.EndsWith("/order/1"))
            {
                if (FailGetOrder)
                {
                    Write(ctx, 500, @"{""type"":""about:blank"",""detail"":""order lookup failed""}");
                    return;
                }
                if (FailGetOrderTimes > 0)
                {
                    FailGetOrderTimes--;
                    Write(ctx, 500, @"{""type"":""about:blank"",""detail"":""transient order lookup failure""}");
                    return;
                }
                var finalizeField = OmitFinalizeUrl ? "" : $@",""finalize"": ""{BaseUrl}finalize/1""";
                var effectiveStatus = OrderStatus;
                if (EmptyOrderStatusTimes > 0)
                {
                    EmptyOrderStatusTimes--;
                    effectiveStatus = "";
                }
                Write(ctx, 200, $@"{{
                    ""status"": ""{effectiveStatus}"",
                    ""authorizations"": [""{BaseUrl}authz/1""]{finalizeField}
                }}");
                return;
            }

            if (path.EndsWith("/authz/1"))
            {
                if (FailGetAuthz)
                {
                    Write(ctx, 500, @"{""type"":""about:blank"",""detail"":""authz lookup failed""}");
                    return;
                }
                Write(ctx, 200, $@"{{
                    ""identifier"": {{ ""type"": ""dns"", ""value"": ""example.com"" }},
                    ""status"": ""{AuthzStatus}"",
                    ""challenges"": [
                        {{ ""type"": ""{ChallengeType}"", ""url"": ""{BaseUrl}chal/1"", ""status"": ""{ChallengeStatus}"", ""token"": ""tok1"" }}
                    ]
                }}");
                return;
            }

            if (path.EndsWith("/chal/1"))
            {
                var requestNumber = Interlocked.Increment(ref _chalRequestCount);
                if (requestNumber == 1 && FailAnswerChallenge)
                {
                    Write(ctx, 500, @"{""type"":""about:blank"",""detail"":""answer challenge failed""}");
                    return;
                }
                if (requestNumber > 1 && FailChallengePollsAfterSubmit)
                {
                    Write(ctx, 500, @"{""type"":""about:blank"",""detail"":""poll failed""}");
                    return;
                }
                var errorField = ChallengeErrorDetail != null
                    ? $@",""error"": {{ ""type"": ""urn:ietf:params:acme:error:dns"", ""detail"": ""{ChallengeErrorDetail}"" }}"
                    : "";
                Write(ctx, 200, $@"{{ ""type"": ""{ChallengeType}"", ""url"": ""{BaseUrl}chal/1"", ""status"": ""{ChallengeStatus}"", ""token"": ""tok1""{errorField} }}");
                return;
            }

            if (path.EndsWith("/finalize/1"))
            {
                if (FinalizeReturnsNullStatus)
                {
                    Write(ctx, 200, $@"{{ ""status"": null, ""authorizations"": [""{BaseUrl}authz/1""], ""finalize"": ""{BaseUrl}finalize/1"" }}");
                    return;
                }
                var certField = FinalizeValidWithoutCertificate ? "" : $@",""certificate"": ""{BaseUrl}cert/1""";
                Write(ctx, 200, $@"{{
                    ""status"": ""valid"",
                    ""authorizations"": [""{BaseUrl}authz/1""],
                    ""finalize"": ""{BaseUrl}finalize/1""{certField}
                }}");
                return;
            }

            if (path.EndsWith("/revoke-cert"))
            {
                if (FailRevoke)
                {
                    Write(ctx, 400, @"{""type"":""urn:ietf:params:acme:error:malformed"",""detail"":""cannot revoke""}");
                    return;
                }
                Write(ctx, 200, "{}");
                return;
            }

            if (path.EndsWith("/cert/1"))
            {
                if (FailCertificate)
                {
                    Write(ctx, 500, @"{""type"":""about:blank"",""detail"":""cert download failed""}");
                    return;
                }
                var bytes = Encoding.UTF8.GetBytes("fake-certificate-bytes");
                ctx.Response.ContentType = "application/pem-certificate-chain";
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentLength64 = bytes.Length;
                ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
                ctx.Response.OutputStream.Close();
                return;
            }

            Write(ctx, 404, @"{""type"":""about:blank"",""detail"":""not found""}");
        }

        private static void Write(HttpListenerContext ctx, int status, string body)
        {
            var bytes = Encoding.UTF8.GetBytes(body);
            ctx.Response.StatusCode = status;
            ctx.Response.ContentLength64 = bytes.Length;
            ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
            ctx.Response.OutputStream.Close();
        }

        public void Dispose()
        {
            _cts.Cancel();
            try { _listener.Stop(); } catch { }
            try { _listener.Close(); } catch { }
        }
    }
}
