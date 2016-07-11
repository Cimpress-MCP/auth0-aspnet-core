using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Cimpress.Auth0.Client
{
    /// <summary>
    /// The auth0 token provider stores and refreshes tokens for specific auth0 clientIds and domains. (As long as the endpoint provides the www-authentication header.)
    /// </summary>
    public interface IAuth0TokenProvider
    {
        /// <summary>
        /// Adds or updates the client asynchronously.
        /// </summary>
        /// <param name="settings">The settings.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <returns></returns>
        Task AddOrUpdateClientAsync(Auth0ClientSettings settings, bool forceRefresh = false);

        /// <summary>
        /// Adds or updates the client asynchronous based on a http response message that contains the www-authentication header.
        /// </summary>
        /// <param name="response">The 401 response message that should include the www-authentication header.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        Task AddOrUpdateClientAsync(HttpResponseMessage response, bool forceRefresh = false);

        /// <summary>
        /// Adds or updates the client asynchronously.
        /// </summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <remarks>
        /// The auth token will be updated also during add.
        /// </remarks>
        Task AddOrUpdateClientAsync(string clientId, bool forceRefresh = false);

        /// <summary>
        /// Gets the authentication header for client asynchronously.
        /// </summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <returns></returns>
        Task<AuthenticationHeaderValue> GetAuthHeaderForClientAsync(string clientId, bool forceRefresh = false);

        /// <summary>
        /// Gets the authentication header for client asynchronously.
        /// </summary>
        /// <param name="response">The 401 response message that should include the www-authentication header.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <param name="clientId">The client id. 
        /// Will be used when the response dose not contain this information. 
        /// Otherwise it will be overruled by the www-authenticate header.</param>
        /// <returns></returns>
        Task<AuthenticationHeaderValue> GetAuthHeaderForClientAsync(HttpResponseMessage response, bool forceRefresh = false, string clientId = "");

        /// <summary>
        /// Gets the authentication header for a domain asynchronously.
        /// </summary>
        /// <param name="host">The host.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <returns></returns>
        Task<AuthenticationHeaderValue> GetAuthHeaderForDomainAsync(string host, bool forceRefresh = false);

        /// <summary>
        /// Locally caches Auth0 settings for a given client based on the <paramref name="settings"/> provided.
        /// If the <paramref name="settings"/> instance doesn't provide certain parameters, the provider falls
        /// back to the submitted default settings.
        /// </summary>
        void CacheAuthSettings(Auth0ClientSettings settings);
    }
}