using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Cimpress.Auth0.Client.Proxies;
using Microsoft.Extensions.Logging;

namespace Cimpress.Auth0.Client
{
    public class Auth0TokenProvider : BaseAuth0TokenProvider, IAuth0TokenProvider
    {
        internal readonly IAutoScheduler autoScheduler;
        private readonly string defaultUsername;
        private readonly string defaultPassword;
        private readonly string defaultConnection;

        /// <summary>
        /// Initializes a new instance of the <see cref="Auth0TokenProvider" /> class.
        /// </summary>
        /// <param name="defaultSettings">The settings.</param>
        /// <param name="autoScheduler">The auto-scheduler that refreshes the Auth0 token after X minutes.</param>
        public Auth0TokenProvider(ILoggerFactory loggerFactory, Auth0ClientSettings defaultSettings,
            IAuthenticationApiClient authenticationApiClient = null, IAutoScheduler autoScheduler = null)
            : base(loggerFactory, defaultSettings, authenticationApiClient, autoScheduler)
        {
            this.autoScheduler = autoScheduler ?? new AutoScheduler(loggerFactory, this);
            defaultPassword = defaultSettings.Auth0Password;
            defaultUsername = defaultSettings.Auth0Username;
            defaultConnection = defaultSettings.Auth0Connection;
        }

        public override void ScheduleAutoRefresh(Auth0ClientSettings auth0ClientSettings)
        {
            autoScheduler.ScheduleRefresh(auth0ClientSettings);
        }

        /// <summary>
        /// Locally caches Auth0 settings for a given client based on the <paramref name="settings"/> provided.
        /// If the <paramref name="settings"/> instance doesn't provide certain parameters, the provider falls
        /// back to the submitted default settings.
        /// </summary>
        public override void CacheAuthSettings(Auth0ClientSettings settings)
        {
            // apply defaults
            settings.Auth0Username = string.IsNullOrWhiteSpace(settings.Auth0Username)
                ? defaultUsername
                : settings.Auth0Username;
            settings.Auth0ClientSecret = string.IsNullOrWhiteSpace(settings.Auth0Password)
                ? defaultPassword
                : settings.Auth0Password;
            settings.Auth0ServerUrl = string.IsNullOrWhiteSpace(settings.Auth0ServerUrl)
                ? defaultDomain
                : settings.Auth0ServerUrl;
            settings.Auth0Connection = string.IsNullOrWhiteSpace(settings.Auth0Connection)
                ? defaultConnection
                : settings.Auth0Connection;
            settings.Auth0RefreshToken = string.IsNullOrWhiteSpace(settings.Auth0RefreshToken)
                ? defaultRefreshToken
                : settings.Auth0RefreshToken;
            settings.AutoRefreshAfter = settings.AutoRefreshAfter == TimeSpan.MinValue
                ? defaultAutoRefreshAfter
                : settings.AutoRefreshAfter;

            // cache settings
            clientTokenCache.TryAdd(settings.Auth0ClientId, settings);
        }

        /// <summary>
        /// Adds or updates the client asynchronously.
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

        /// <summary>
        /// Refactoring Auth0TokenProvider functionality to support multiple types.
        /// Updates the auth0 authentication header for the client id using username and password asynchronous.
        /// </summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="forceRefresh">if set to <c>true</c> [force refresh].</param>
        /// <returns>
        /// A task, when completed, ensures that the authentication header got updated.
        /// </returns>
        /// <exception cref="System.Collections.Generic.KeyNotFoundException"></exception>
        public override async Task UpdateAuthHeaderWithCredentialsAsync(string clientId, bool forceRefresh = false)
        {
            if (await syncObject.WaitAsync(5000))
            {
                try
                {
                    if (!clientTokenCache.ContainsKey(clientId))
                    {
                        throw new KeyNotFoundException(
                            $"Cannot update the auth token for client {clientId}, because of missing information.");
                    }

                    // Only update if really needed. 
                    // Especially when multiple tasks are invoked at the same time we only need to update once.
                    // Testing for a valid token happens within GetAuthHeaderForClient but outside of the locked section.
                    // Therefore it might happen that the token was already updated once entering the locked section.
                    if (clientTokenCache[clientId].LastRefresh > DateTimeOffset.Now.AddSeconds(-5) && !forceRefresh)
                    {
                        return;
                    }

                    var request = new RoAuthenticationRequestDto
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
                    var authToken =
                        await
                            authenticationApiClient.AuthenticateAsync(request, clientTokenCache[clientId].Auth0ServerUrl);

                    // set the authorization header
                    clientTokenCache[clientId].Auth0HeaderValue = new AuthenticationHeaderValue("Bearer", authToken.IdToken);
                    clientTokenCache[clientId].LastRefresh = DateTimeOffset.Now;
                    logger.LogInformation($"Successfully authenticated with the service client id {clientId} with username and password.");
                    ScheduleAutoRefresh(clientTokenCache[clientId]);
                }
                catch (Exception ex)
                {
                    // any exceptions during authentication are logged here
                    logger.LogError(
                        $"Error authenticating with service: {clientId} using user {clientTokenCache[clientId].Auth0Username}.",
                        ex);
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
    }
}
