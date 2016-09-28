using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Cimpress.Auth0.Client.Proxies;
using Microsoft.Extensions.Logging;

namespace Cimpress.Auth0.Client
{
    public abstract class BaseAuth0TokenProvider
    {
        public readonly IAuthenticationApiClient authenticationApiClient;
        public readonly ConcurrentDictionary<string, Auth0ClientSettings> clientTokenCache;
        public readonly ConcurrentDictionary<string, string> domainClientIdCache;
        public readonly string defaultDomain;
        public readonly string defaultRefreshToken;
        public readonly TimeSpan defaultAutoRefreshAfter;

        public readonly ILogger logger;
        public readonly SemaphoreSlim syncObject = new SemaphoreSlim(1);

        protected BaseAuth0TokenProvider(ILoggerFactory loggerFactory, Auth0ClientSettings defaultSettings, IAuthenticationApiClient authenticationApiClient)
        {
            this.authenticationApiClient = authenticationApiClient ?? new AuthenticationApiClient();
            clientTokenCache = new ConcurrentDictionary<string, Auth0ClientSettings>();
            domainClientIdCache = new ConcurrentDictionary<string, string>();
            logger = loggerFactory.CreateLogger<BaseAuth0TokenProvider>();
            defaultDomain = defaultSettings.Auth0ServerUrl;
            defaultRefreshToken = defaultSettings.Auth0RefreshToken;
            defaultAutoRefreshAfter = defaultSettings.AutoRefreshAfter;
        }

        public abstract void ScheduleAutoRefresh(Auth0ClientSettings auth0ClientSettings);
        public abstract void CacheAuthSettings(Auth0ClientSettings settings);
        public abstract Task UpdateAuthHeaderWithCredentialsAsync(string clientId, bool forceRefresh);

        /// <summary>
        /// Adds or updates the client asynchronously.
        /// </summary>
        /// <param name="settings">The settings.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <remarks>Set to false during injection of pre-known clients to speed up initialization.</remarks>
        public async Task AddOrUpdateClientAsync(Auth0ClientSettings settings, bool forceRefresh = false)
        {
            CacheAuthSettings(settings);
            await UpdateAuthHeaderAsync(settings.Auth0ClientId, forceRefresh);
        }
        
        /// <summary>
        /// Adds or updates the client asynchronously.
        /// </summary>
        /// <param name="response">The 401 response message that should include the www-authentication header.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        public async Task AddOrUpdateClientAsync(HttpResponseMessage response, bool forceRefresh = false)
        {
            var clientInfo = GetSettingsFromResponseHeader(response.Headers.WwwAuthenticate);
            await AddOrUpdateClientAsync(clientInfo, forceRefresh);
            domainClientIdCache.AddOrUpdate(response.RequestMessage.RequestUri.Host, clientInfo.Auth0ClientId, (key, value) => clientInfo.Auth0ClientId);
        }

        /// <summary>
        /// Adds or updates the client asynchronously.
        /// </summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <remarks>
        /// The auth token will be updated also during add.
        /// </remarks>
        public async Task AddOrUpdateClientAsync(string clientId, bool forceRefresh = false)
        {
            await AddOrUpdateClientAsync(new Auth0ClientSettings { Auth0ClientId = clientId }, forceRefresh);
        }

        /// <summary>
        /// Gets the authentication header for client asynchronously.
        /// </summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <returns></returns>
        public async Task<AuthenticationHeaderValue> GetAuthHeaderForClientAsync(string clientId, bool forceRefresh = false)
        {
            Auth0ClientSettings clientSettings;
            clientTokenCache.TryGetValue(clientId, out clientSettings);
            if (clientSettings?.Auth0HeaderValue == null || forceRefresh)
            {
                await AddOrUpdateClientAsync(clientSettings ?? new Auth0ClientSettings { Auth0ClientId = clientId }, forceRefresh);
                clientTokenCache.TryGetValue(clientId, out clientSettings);
            }

            return clientSettings?.Auth0HeaderValue;
        }

        /// <summary>
        /// Gets the authentication header for client asynchronously.
        /// </summary>
        /// <param name="response">The 401 response message that should include the www-authentication header.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <param name="clientId">The client id. 
        /// Will be used when the response dose not contain this information. 
        /// Otherwise it will be overruled by the www-authenticate header.</param>
        /// <returns></returns>
        public async Task<AuthenticationHeaderValue> GetAuthHeaderForClientAsync(HttpResponseMessage response, bool forceRefresh = false, string clientId = null)
        {
            var clientInfo = GetSettingsFromResponseHeader(response.Headers.WwwAuthenticate);
            Auth0ClientSettings result;

            // Maybe the called service does not provide a www-authenticate header and we already know the client id - use it.
            if (string.IsNullOrWhiteSpace(clientInfo?.Auth0ClientId) && !string.IsNullOrWhiteSpace(clientId))
            {
                return await GetAuthHeaderForClientAsync(clientId, forceRefresh);
            }

            clientTokenCache.TryGetValue(clientInfo?.Auth0ClientId, out result);

            if (result?.Auth0HeaderValue == null || forceRefresh)
            {
                await AddOrUpdateClientAsync(response, forceRefresh);
                clientTokenCache.TryGetValue(clientInfo?.Auth0ClientId, out result);
            }

            return result?.Auth0HeaderValue;
        }

        /// <summary>
        /// Gets the authentication header for a domain asynchronously.
        /// </summary>
        /// <param name="host">The host.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <returns></returns>
        public async Task<AuthenticationHeaderValue> GetAuthHeaderForDomainAsync(string host, bool forceRefresh = false)
        {
            string clientId;
            if (domainClientIdCache.TryGetValue(host, out clientId))
            {
                return await GetAuthHeaderForClientAsync(clientId, forceRefresh);
            }

            return null;
        }

        /// <summary>
        /// Updates the auth0 authentication header for the client (either with user name/password or with a refresh token).
        /// </summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <returns>
        /// A task, when completed, ensures that the authentication header got updated.
        /// </returns>
        /// <exception cref="System.Collections.Generic.KeyNotFoundException"></exception>
        private async Task UpdateAuthHeaderAsync(string clientId, bool forceRefresh = false)
        {
            Auth0ClientSettings settings;
            clientTokenCache.TryGetValue(clientId, out settings);
            if (settings == null)
            {
                throw new KeyNotFoundException($"Cannot update the auth token for client {clientId}, because of missing information.");
            }

            if (string.IsNullOrWhiteSpace(settings.Auth0RefreshToken))
            {
                await UpdateAuthHeaderWithCredentialsAsync(clientId, forceRefresh);
            }
            else
            {
                await UpdateAuthHeaderWithRefreshTokenAsync(clientId, forceRefresh);
            }
        }
        
        /// <summary>
        /// Updates the authentication header using the refresh token asynchronous.
        /// </summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <exception cref="System.Collections.Generic.KeyNotFoundException"></exception>
        private async Task UpdateAuthHeaderWithRefreshTokenAsync(string clientId, bool forceRefresh = false)
        {
            if (await syncObject.WaitAsync(5000))
            {
                try
                {
                    if (!clientTokenCache.ContainsKey(clientId))
                    {
                        throw new KeyNotFoundException($"Cannot update the auth token for client {clientId}, because of missing information.");
                    }

                    // Only update if really needed. 
                    // Especially when multiple tasks are invoked at the same time we only need to update once.
                    // Testing for a valid token happens within GetAuthHeaderForClient but outside of the locked section.
                    // Therefore it might happen that the token was already updated once entering the locked section.
                    if (clientTokenCache[clientId].LastRefresh > DateTimeOffset.Now.AddSeconds(-5) && !forceRefresh)
                    {
                        return;
                    }

                    var refreshRequest = new RefreshTokenDelegationRequestDto(clientId, clientId, clientTokenCache[clientId].Auth0RefreshToken);

                    // authenticate with auth0
                    var authToken = await authenticationApiClient.GetDelegationTokenAsync(refreshRequest, clientTokenCache[clientId].Auth0ServerUrl);

                    // set the authorization header
                    clientTokenCache[clientId].Auth0HeaderValue = new AuthenticationHeaderValue("Bearer", authToken.IdToken);
                    clientTokenCache[clientId].LastRefresh = DateTimeOffset.Now;
                    logger.LogInformation($"Successfully authenticated with the service client id {clientId} with refresh token.");

                    ScheduleAutoRefresh(clientTokenCache[clientId]);
                }
                catch (Exception ex)
                {
                    // any exceptions during authentication are logged here
                    logger.LogError($"Error authenticating with service: {clientId} using refresh token {clientTokenCache[clientId].Auth0RefreshToken}.", ex);
                }
                finally
                {
                    syncObject.Release();
                }
            }
            else
            {
                logger.LogWarning("Auth0TokenProvider could not get lock for retrieving an authentication token.");
            }
        }

        internal void ScheduleAutoRefresh(Auth0ClientSettings auth0ClientSettings, IAutoScheduler autoScheduler)
        {
            autoScheduler.ScheduleRefresh(auth0ClientSettings);
        }

        private Auth0ClientSettings GetSettingsFromResponseHeader(HttpHeaderValueCollection<AuthenticationHeaderValue> wwwAuthenticationHeaderValues)
        {
            var result = new Auth0ClientSettings();

            foreach (var authenticationHeaderValue in wwwAuthenticationHeaderValues)
            {
                if (authenticationHeaderValue.Scheme.ToLowerInvariant() == "bearer")
                {
                    // The header looks like this: WWW-Authenticate: Bearer realm="example.auth0.com", scope="client_id=xxxxxxxxxx service=https://myservice.example.com"
                    // First we have to split on white spaces that are not within '" "'.
                    var parameters = Regex.Matches(authenticationHeaderValue.Parameter, "\\w+\\=\\\".*?\\\"|\\w+[^\\s\\\"]+?");

                    foreach (var param in parameters)
                    {
                        var parameterstring = param.ToString();
                        var info = parameterstring.Trim().Split('=');
                        if (info.Length < 2)
                        {
                            continue;
                        }

                        // Realm has only 1 value.
                        if ((info[0].ToLowerInvariant()) == "realm")
                        {
                            var domain = info[1].Replace("\"", "");
                            domain = domain.ToLowerInvariant().StartsWith("http") ? domain : $"https://{domain}";
                            result.Auth0ServerUrl = domain;
                            continue;
                        }

                        // Within the scope we can have multiple key/value pairs separated by white space.
                        if (info[0].ToLowerInvariant() == "scope")
                        {
                            var scopes = parameterstring.Substring(info[0].Length + 1).Replace("\"", "").Split(' ');
                            foreach (var scope in scopes)
                            {
                                var splittedScope = scope.Split('=');
                                if (splittedScope.Length < 2)
                                {
                                    continue;
                                }

                                // We are interested in the client id.
                                if ((splittedScope[0]?.ToLowerInvariant() ?? "") == "client_id")
                                {
                                    result.Auth0ClientId = splittedScope[1];
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            return result;
        }
    }
}
