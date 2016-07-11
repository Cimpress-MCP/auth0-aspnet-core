using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Cimpress.Auth0.Client.Proxies
{
    /// <summary>
    /// Client for communicating with the Auth0 Authentication API.
    /// </summary>
    /// <remarks>
    /// Full documentation for the Authentication API is available at https://auth0.com/docs/auth-api
    /// This has been copied and slightly adapterd from https://github.com/auth0/auth0.net since it doesn't yet support netcore.
    /// </remarks>
    public class AuthenticationApiClient
    {
        private readonly HttpClient httpClient;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticationApiClient" /> class.
        /// </summary>
        /// <param name="baseUri">The base URI.</param>
        public AuthenticationApiClient(Uri baseUri)
        {
            httpClient = new HttpClient { BaseAddress = baseUri };
        }
        
        /// <summary>
        /// Given an <see cref="AuthenticationRequestDto" />, it will do the authentication on the provider and return a <see cref="AuthenticationResponseDto" />
        /// </summary>
        /// <param name="request">The authentication request details containing information regarding the connection, username, password etc.</param>
        /// <returns>A <see cref="AuthenticationResponseDto" /> with the access token.</returns>
        public Task<AuthenticationResponseDto> AuthenticateAsync(AuthenticationRequestDto request)
        {
            return PostAsync<AuthenticationResponseDto>("/oauth/ro", request);
        }

        /// <summary>
        /// Given an existing token, this endpoint will generate a new token signed with the target client secret. This is used to flow the identity of the user from the application to an API or across different APIs that are protected with different secrets.
        /// </summary>
        /// <param name="request">The <see cref="DelegationRequestBaseDto" /> containing details about the request.</param>
        /// <returns>The <see cref="AccessToken" />.</returns>
        public Task<AccessToken> GetDelegationTokenAsync(DelegationRequestBaseDto request)
        {
            return PostAsync<AccessToken>("/delegation", request);
        }

        /// <summary>
        /// Performs an HTTP POST.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="resource">The resource.</param>
        /// <param name="body">The body.</param>
        /// <returns>Task&lt;T&gt;.</returns>
        private async Task<T> PostAsync<T>(string resource, object body) where T : class
        {
            var content = new StringContent(JsonConvert.SerializeObject(body, new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore }), Encoding.UTF8, "application/json");

            // Send the request
            var response = await httpClient.PostAsync(resource, content);

            // Handle API errors
            await response.LogAndThrowIfNotSuccessStatusCode(null);

            // Deserialize the content
            string result = await response.Content.ReadAsStringAsync();

            // Let string content pass through
            if (typeof(T) == typeof(string))
            {
                return (T)(object)content;
            }

            // convert result to an object
            return JsonConvert.DeserializeObject<T>(result);
        }
    }
}
