using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using Microsoft.Extensions.Logging;
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.Acme.Clients.Acme
{
    /// <summary>
    /// Extension methods for AcmeProtocolClient that provide robust error handling,
    /// retry logic, and rate limiting support according to ACME protocol standards.
    /// </summary>
    internal static class AcmeClientExtensions
    {
        /// <summary>
        /// Semaphore to prevent simultaneous requests to the ACME service.
        /// This is critical because simultaneous requests can interfere with 
        /// the nonce tracking mechanism required by the ACME protocol.
        /// </summary>
        private static readonly SemaphoreSlim _requestLock = new(1, 1);

        /// <summary>
        /// Maximum number of retry attempts for bad nonce errors
        /// </summary>
        private const int MaxNonceRetries = 3;

        /// <summary>
        /// Maximum number of backoff attempts for general ACME errors
        /// </summary>
        private const int MaxBackoffAttempts = 5;

        /// <summary>
        /// Base delay in milliseconds for backoff retry attempts
        /// </summary>
        private const int BaseDelayMs = 1000;

        /// <summary>
        /// Retrieves a new nonce from the ACME server for use in subsequent requests.
        /// Nonces are required by the ACME protocol to prevent replay attacks.
        /// </summary>
        /// <param name="client">The ACME protocol client</param>
        /// <param name="log">Logger for capturing diagnostic information</param>
        /// <returns>Task that completes when the nonce is obtained</returns>
        private static async Task GetNonce(this AcmeProtocolClient client, ILogger log)
        {
            await client.Backoff(async () =>
            {
                await client.GetNonceAsync();
                return 1; // Return value is ignored, just needed for generic method
            }, log);
        }

        /// <summary>
        /// Executes an ACME operation with automatic retry logic for bad nonce errors.
        /// According to RFC 8555 (ACME specification), clients SHOULD retry requests
        /// that fail due to invalid nonces, as nonces can become stale.
        /// </summary>
        /// <typeparam name="T">The return type of the operation</typeparam>
        /// <param name="client">The ACME protocol client</param>
        /// <param name="executor">The operation to execute</param>
        /// <param name="log">Logger for capturing diagnostic information</param>
        /// <param name="attempt">Current retry attempt number (0-based)</param>
        /// <returns>The result of the executed operation</returns>
        /// <exception cref="AcmeProtocolException">Thrown when ACME protocol errors occur that cannot be retried</exception>
        /// <exception cref="Exception">Thrown when unexpected errors occur</exception>
        internal static async Task<T> Retry<T>(
            this AcmeProtocolClient client,
            Func<Task<T>> executor,
            ILogger log,
            int attempt = 0)
        {
            // Acquire the semaphore on the first attempt to prevent concurrent requests
            if (attempt == 0)
            {
                await _requestLock.WaitAsync();
            }

            try
            {
                return await client.Backoff(async () =>
                {
                    // Ensure we have a valid nonce before making the request
                    if (string.IsNullOrEmpty(client.NextNonce))
                    {
                        await client.GetNonce(log);
                    }

                    // Execute the actual operation - exceptions are intentionally not caught here
                    // to allow proper error handling in the outer catch blocks
                    return await executor();
                }, log);
            }
            catch (AcmeProtocolException apex)
            {
                // Handle bad nonce errors with retry logic (up to 3 attempts)
                if (attempt < MaxNonceRetries && apex.ProblemType == ProblemType.BadNonce)
                {
                    log.LogWarning("Bad nonce error occurred on attempt {Attempt}, retrying with fresh nonce...", attempt + 1);
                    await client.GetNonce(log);
                    return await client.Retry(executor, log, attempt + 1);
                }
                // Handle user action required errors (non-retryable)
                else if (apex.ProblemType == ProblemType.UserActionRequired)
                {
                    log.LogError("User action required: {Detail} (Problem Type: {ProblemType})",
                        apex.ProblemDetail, apex.ProblemType);
                    throw;
                }

                // Log and re-throw all other ACME protocol exceptions
                log.LogError("ACME Protocol Exception: {Message}", apex.Message);
                throw;
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Unexpected error occurred during ACME operation retry");
                throw;
            }
            finally
            {
                // Release the semaphore only on the initial attempt to avoid double-release
                if (attempt == 0)
                {
                    _requestLock.Release();
                }
            }
        }

        /// <summary>
        /// Executes an ACME operation with exponential backoff retry logic for transient errors.
        /// This handles temporary server issues and implements a progressive delay strategy
        /// to avoid overwhelming busy servers.
        /// </summary>
        /// <typeparam name="T">The return type of the operation</typeparam>
        /// <param name="client">The ACME protocol client</param>
        /// <param name="executor">The operation to execute</param>
        /// <param name="log">Logger for capturing diagnostic information</param>
        /// <param name="attempt">Current retry attempt number (0-based)</param>
        /// <returns>The result of the executed operation</returns>
        /// <exception cref="AcmeProtocolException">Thrown when rate limits are hit (non-retryable)</exception>
        /// <exception cref="Exception">Thrown when maximum retry attempts are exceeded</exception>
        internal static async Task<T> Backoff<T>(
            this AcmeProtocolClient client,
            Func<Task<T>> executor,
            ILogger log,
            int attempt = 0)
        {
            try
            {
                return await executor();
            }
            catch (AcmeProtocolException ape)
            {
                // Rate limiting errors should not be retried as they indicate
                // the client has exceeded the server's request limits
                if (ape.ProblemType == ProblemType.RateLimited)
                {
                    log.LogWarning("Rate limit exceeded: {Detail}", ape.ProblemDetail);
                    throw; // Don't retry rate-limited requests
                }

                // Stop retrying after maximum attempts to prevent infinite loops
                if (attempt >= MaxBackoffAttempts)
                {
                    log.LogError("Maximum retry attempts ({MaxAttempts}) exceeded", MaxBackoffAttempts);
                    throw new Exception($"ACME service is too busy after {MaxBackoffAttempts} attempts, try again later", ape);
                }

                // Log the error and implement exponential backoff delay
                log.LogWarning("ACME error on attempt {Attempt}, retrying in {Delay}ms: {Detail}",
                    attempt + 1, BaseDelayMs * (attempt + 1), ape.ProblemDetail);

                // Exponential backoff: delay increases with each attempt
                await Task.Delay(BaseDelayMs * (attempt + 1));

                return await client.Backoff(executor, log, attempt + 1);
            }
        }
    }
}