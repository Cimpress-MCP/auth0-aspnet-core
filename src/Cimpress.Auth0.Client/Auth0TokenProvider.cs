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
    public class Auth0TokenProvider : IAuth0TokenProvider
    {
        private readonly ConcurrentDictionary<string, Auth0ClientSettings> clientTokenCache;
        private readonly ConcurrentDictionary<string, string> domainClientIdCache;
        private readonly string defaultUsername;
        private readonly string defaultPassword;
        private readonly string defaultDomain;
        private readonly string defaultConnection;

        private readonly ILogger logger;
        private readonly SemaphoreSlim syncObject = new SemaphoreSlim(1);

        /// <summary>
        /// Initializes a new instance of the <see cref="Auth0TokenProvider" /> class.
        /// </summary>
        /// <param name="loggerFactory">The logger factory.</param>
        /// <param name="defaultSettings">The settings.</param>
        public Auth0TokenProvider(ILoggerFactory loggerFactory, Auth0ClientSettings defaultSettings)
        {
            clientTokenCache = new ConcurrentDictionary<string, Auth0ClientSettings>();
            domainClientIdCache = new ConcurrentDictionary<string, string>();
            logger = loggerFactory.CreateLogger<Auth0TokenProvider>();
            defaultDomain = defaultSettings.Auth0ServerUrl;
            defaultPassword = defaultSettings.Auth0Password;
            defaultUsername = defaultSettings.Auth0Username;
            defaultConnection = defaultSettings.Auth0Connection;
        }

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
        /// Locally caches Auth0 settings for a given client based on the <paramref name="settings"/> provided.
        /// If the <paramref name="settings"/> instance doesn't provide certain parameters, the provider falls
        /// back to the submitted default settings.
        /// </summary>
        public void CacheAuthSettings(Auth0ClientSettings settings)
        {
            settings.Auth0Username = string.IsNullOrWhiteSpace(settings.Auth0Username)
                ? defaultUsername
                : settings.Auth0Username;
            settings.Auth0Password = string.IsNullOrWhiteSpace(settings.Auth0Password)
                ? defaultPassword
                : settings.Auth0Password;
            settings.Auth0ServerUrl = string.IsNullOrWhiteSpace(settings.Auth0ServerUrl)
                ? defaultDomain
                : settings.Auth0ServerUrl;
            settings.Auth0Connection = string.IsNullOrWhiteSpace(settings.Auth0Connection)
                ? defaultConnection
                : settings.Auth0Connection;
            settings.Auth0RefreshToken = settings.Auth0RefreshToken;
            clientTokenCache.TryAdd(settings.Auth0ClientId, settings);
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
            await AddOrUpdateClientAsync(new Auth0ClientSettings { Auth0ClientId = clientId}, forceRefresh);
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
                await AddOrUpdateClientAsync(clientSettings ?? new Auth0ClientSettings {Auth0ClientId = clientId}, forceRefresh);
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
                await UpdateAuthHeaderWithUsernameAndPasswordAsync(clientId, forceRefresh);
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
                    if (clientTokenCache[clientId].LastRefresh > DateTime.Now.AddSeconds(-5) && !forceRefresh)
                    {
                        return;
                    }

                    var c = new AuthenticationApiClient(new Uri(clientTokenCache[clientId].Auth0ServerUrl));

                    var refreshRequest = new RefreshTokenDelegationRequestDto(clientId, clientId, clientTokenCache[clientId].Auth0RefreshToken);

                    // authenticate with auth0
                    var authToken = await c.GetDelegationTokenAsync(refreshRequest);

                    // set the authorization header
                    clientTokenCache[clientId].Auth0HeaderValue = new AuthenticationHeaderValue("Bearer", authToken.IdToken);
                    clientTokenCache[clientId].LastRefresh = DateTime.Now;
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

        /// <summary>
        /// Updates the auth0 authentication header for the client id using username and password asynchronous.
        /// </summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <returns>
        /// A task, when completed, ensures that the authentication header got updated.
        /// </returns>
        /// <exception cref="System.Collections.Generic.KeyNotFoundException"></exception>
        private async Task UpdateAuthHeaderWithUsernameAndPasswordAsync(string clientId, bool forceRefresh = false)
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
                    if (clientTokenCache[clientId].LastRefresh > DateTime.Now.AddSeconds(-5) && !forceRefresh)
                    {
                        return;
                    }

                    var c = new AuthenticationApiClient(new Uri(clientTokenCache[clientId].Auth0ServerUrl));
                    var request = new AuthenticationRequestDto
                    {
                        ClientId = clientId, // client ID from bucket service Auth0 app
                        Username = clientTokenCache[clientId].Auth0Username, // auth0 user
                        Password = clientTokenCache[clientId].Auth0Password, // the corresponding password
                        Scope = "openid", // we want openID process
                        Connection = clientTokenCache[clientId].Auth0Connection, // auth0 connection
                        GrantType = "password", // it should be granted based on our password
                        Device = "api" // we want to access an API
                    };

                    // authenticate with auth0
                    var authToken = await c.AuthenticateAsync(request);

                    // set the authorization header
                    clientTokenCache[clientId].Auth0HeaderValue = new AuthenticationHeaderValue("Bearer", authToken.IdToken);
                    clientTokenCache[clientId].LastRefresh = DateTime.Now;
                    logger.LogInformation($"Successfully authenticated with the service client id {clientId} with username and password.");

                    ScheduleAutoRefresh(clientTokenCache[clientId]);
                }
                catch (Exception ex)
                {
                    // any exceptions during authentication are logged here
                    logger.LogError($"Error authenticating with service: {clientId} using user {clientTokenCache[clientId].Auth0Username}.", ex);
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

        private void ScheduleAutoRefresh(Auth0ClientSettings auth0ClientSettings)
        {
            // do not auto-refresh 
            if (auth0ClientSettings.AutoRefreshAfter <= TimeSpan.Zero)
            {
                logger.LogDebug($"Not scheduling an automatic refresh of the Bearer token for client_id {auth0ClientSettings.Auth0ClientId} " +
                                $"and auto-refresh settings {auth0ClientSettings.AutoRefreshAfter}.");
                return;
            }

            Task.Run(async () =>
            {
                try
                {
                    logger.LogInformation($"Scheduling an automatic refresh of the Bearer token for client_id {auth0ClientSettings.Auth0ClientId} in {auth0ClientSettings.AutoRefreshAfter}.");
                    // wait for the specified time
                    await Task.Delay(auth0ClientSettings.AutoRefreshAfter);
                    await UpdateAuthHeaderAsync(auth0ClientSettings.Auth0ClientId);
                }
                catch (Exception ex)
                {
                    logger.LogError(0, ex, $"Error while refreshing the Bearer token for client_id {auth0ClientSettings.Auth0ClientId}. Triggering next schedule.");
                    ScheduleAutoRefresh(auth0ClientSettings);
                }
            });
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
