using System;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Cimpress.Auth0.Client.Proxies;
using Microsoft.Extensions.Logging;

namespace Cimpress.Auth0.Client
{
    public class Auth0v2TokenProvider : BaseAuth0TokenProvider, IAuth0TokenProvider
    {
        private readonly IAutoScheduler autoScheduler;
        private readonly string defaultClientSecret;
        private readonly string defaultAudience;

        /// <summary>
        /// Initializes a new instance of the <see cref="Auth0v2TokenProvider" /> class.
        /// </summary>
        /// <param name="defaultSettings">The settings.</param>
        /// <param name="autoScheduler">The auto-scheduler that refreshes the Auth0 token after X minutes.</param>
        public Auth0v2TokenProvider(ILoggerFactory loggerFactory, Auth0ClientSettings defaultSettings, IAuthenticationApiClient authenticationApiClient = null, IAutoScheduler autoScheduler = null) : base(loggerFactory, defaultSettings, authenticationApiClient)
        {
            this.autoScheduler = autoScheduler ?? new AutoScheduler(loggerFactory, this);
            defaultClientSecret = defaultSettings.Auth0ClientSecret;
            defaultAudience = defaultSettings.Auth0Audience;
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
            settings.Auth0ClientSecret = string.IsNullOrWhiteSpace(settings.Auth0ClientSecret)
                ? defaultClientSecret
                : settings.Auth0ClientSecret;
            settings.Auth0Audience = string.IsNullOrWhiteSpace(settings.Auth0Audience)
                ? defaultAudience
                : settings.Auth0Audience;
            settings.Auth0ServerUrl = string.IsNullOrWhiteSpace(settings.Auth0ServerUrl)
                ? defaultDomain
                : settings.Auth0ServerUrl;
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

                    var request = new TokenAuthenticationRequestDto
                    {
                        ClientId = clientId, // client ID of auth0 app configured to authenticate against target Auth0 API
                        ClientSecret = clientTokenCache[clientId].Auth0ClientSecret, // auth0 client secret
                        Audience = clientTokenCache[clientId].Auth0Audience, //audience url 
                        GrantType = "client_credentials", // it should be granted based on client id/secret
                    };

                    // authenticate with auth0
                    var authToken = await authenticationApiClient.TokenAuthenticateAsync(request, clientTokenCache[clientId].Auth0ServerUrl);

                    // set the authorization header
                    clientTokenCache[clientId].Auth0HeaderValue = new AuthenticationHeaderValue("Bearer", authToken.IdToken);
                    clientTokenCache[clientId].LastRefresh = DateTimeOffset.Now;
                    logger.LogInformation($"Successfully authenticated with the service client id {clientId} with client secret.");

                    ScheduleAutoRefresh(clientTokenCache[clientId], autoScheduler);
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
    }
}
