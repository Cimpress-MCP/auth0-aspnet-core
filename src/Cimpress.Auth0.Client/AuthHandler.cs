using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Cimpress.Auth0.Client
{
    /// <summary>
    /// HTTP message handler that sets authorization headers in order to authenticate
    /// against Auth0. Can be used along with other (nested) handlers in order to provide
    /// automated authentication.
    /// </summary>
    public class AuthHandler : DelegatingHandler
    {
        public ILogger Logger { get; set; }
        public IAuth0TokenProvider Auth0TokenProvider { get; }
        public string Auth0ClientId { get; }


        public AuthHandler(ILogger logger, IAuth0TokenProvider auth0TokenProvider = null, string auth0ClientId = "") : this(new HttpClientHandler(), logger, auth0TokenProvider, auth0ClientId)
        {
        }

        public AuthHandler(HttpMessageHandler innerHandler, ILogger logger, IAuth0TokenProvider auth0TokenProvider = null, string auth0ClientId = "") : base(innerHandler)
        {
            Logger = logger;
            Auth0TokenProvider = auth0TokenProvider;
            Auth0ClientId = auth0ClientId;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await SetAuthHeader(request);

            HttpResponseMessage response = await base.SendAsync(request, cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                return response;
            }

            //retry in case of an expired token
            if (response.StatusCode == HttpStatusCode.Unauthorized && Auth0TokenProvider != null)
            {
                Logger.LogWarning($"Unauthorized invocation of REST service at {request.RequestUri}. Trying to get a new auth0 token.");

                // Either the auth0 token expired or we have a domain where we do not know the client id in advance.
                request.Headers.Authorization = await Auth0TokenProvider.GetAuthHeaderForClientAsync(response, true, Auth0ClientId);
                response = await base.SendAsync(request, cancellationToken);
            }

            return response;
        }

        protected async Task SetAuthHeader(HttpRequestMessage request)
        {
            if (Auth0TokenProvider != null)
            {
                // The auth0 client id is already known, so we can directly use the token from the token provider.
                if (!string.IsNullOrWhiteSpace(Auth0ClientId))
                {
                    request.Headers.Authorization = await Auth0TokenProvider.GetAuthHeaderForClientAsync(Auth0ClientId);
                }
                // Maybe we already have a token for the host – then use it.
                // If the host requires auth0 we’ll be noticed during 1st retry and can then extract the auth0 client id from the www-authentication header and use it for consecutive invocations.
                else
                {
                    var auth0Header = await Auth0TokenProvider.GetAuthHeaderForDomainAsync(request.RequestUri.Host);
                    if (auth0Header != null)
                    {
                        request.Headers.Authorization = auth0Header;
                    }
                }
            }
        }
    }
}