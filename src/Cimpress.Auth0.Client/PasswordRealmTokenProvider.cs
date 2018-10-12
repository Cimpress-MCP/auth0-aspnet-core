using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Cimpress.Auth0.Client.Proxies;
using Microsoft.Extensions.Logging;

namespace Cimpress.Auth0.Client
{
    public class PasswordRealmTokenProvider : IAuth0TokenProvider
    {
        private readonly IAutoScheduler autoScheduler;
        private readonly Auth0ClientSettings currentSettings;
        private readonly SemaphoreSlim syncObject = new SemaphoreSlim(1);
        private readonly IAuthenticationApiClient authenticationApiClient;
        private readonly ILogger logger;
        public bool RefreshTokenWhenUnauthorized { get; set; } = true;

        public PasswordRealmTokenProvider(ILoggerFactory loggerFactory, Auth0ClientSettings currentSettings, IAuthenticationApiClient authenticationApiClient = null,
            IAutoScheduler autoScheduler = null)
        {
            logger = loggerFactory.CreateLogger<PasswordRealmTokenProvider>();
            this.authenticationApiClient = authenticationApiClient ?? new AuthenticationApiClient();
            this.autoScheduler = autoScheduler ?? new AutoScheduler(loggerFactory, this);
            this.currentSettings = currentSettings;
            this.currentSettings.Auth0Realm = currentSettings.Auth0Realm ?? "default";
            this.currentSettings.Auth0GrantType = currentSettings.Auth0GrantType ?? "http://auth0.com/oauth/grant-type/password-realm";
        }

        public void ScheduleAutoRefresh(Auth0ClientSettings auth0ClientSettings)
        {
            autoScheduler.ScheduleRefresh(auth0ClientSettings);
        }

        public async Task AddOrUpdateClientAsync(Auth0ClientSettings settings, bool forceRefresh = false)
        {
            await UpdateAuthHeaderAsync(null, forceRefresh);
        }

        public async Task AddOrUpdateClientAsync(HttpResponseMessage response, bool forceRefresh = false)
        {
            await UpdateAuthHeaderAsync(null, forceRefresh);
        }

        public async Task AddOrUpdateClientAsync(string clientId, bool forceRefresh = false)
        {
            await UpdateAuthHeaderAsync(null, forceRefresh);
        }

        public async Task<AuthenticationHeaderValue> GetAuthHeaderForClientAsync(string clientId, bool forceRefresh = false)
        {
            if (currentSettings.Auth0HeaderValue == null || forceRefresh)
            {
                await UpdateAuthHeaderAsync(null, forceRefresh);
            }
            return currentSettings.Auth0HeaderValue;
        }

        public async Task<AuthenticationHeaderValue> GetAuthHeaderForClientAsync(HttpResponseMessage response, bool forceRefresh = false, string clientId = "")
        {
            return await GetAuthHeaderForClientAsync(null, forceRefresh);
        }

        public async Task<AuthenticationHeaderValue> GetAuthHeaderForDomainAsync(string host, bool forceRefresh = false)
        {
            return await GetAuthHeaderForClientAsync(null, forceRefresh);
        }

        public void CacheAuthSettings(Auth0ClientSettings settings)
        {
            currentSettings.LastRefresh = settings.LastRefresh;
            currentSettings.Auth0HeaderValue = settings.Auth0HeaderValue;
        }

        public async Task UpdateAuthHeaderAsync(string clientId, bool forceRefresh)
        {
            if (await syncObject.WaitAsync(10000))
            {
                try
                {
                    // Only update if really needed. 
                    // Especially when multiple tasks are invoked at the same time we only need to update once.
                    // Testing for a valid token happens within GetAuthHeaderForClient but outside of the locked section.
                    // Therefore it might happen that the token was already updated once entering the locked section.
                    if (currentSettings.Auth0HeaderValue != null && currentSettings.LastRefresh > DateTimeOffset.Now.AddSeconds(-5) && !forceRefresh)
                    {
                        return;
                    }

                    var request = new PasswordRealmAuthenticationRequestDto
                    {
                        ClientId = currentSettings.Auth0ClientId,
                        Audience = currentSettings.Auth0Audience,
                        GrantType = currentSettings.Auth0GrantType,
                        Password = currentSettings.Auth0Password,
                        Username = currentSettings.Auth0Username,
                        Realm = currentSettings.Auth0Realm
                    };

                    // authenticate with auth0
                    var authToken = await authenticationApiClient.PasswordRealmAuthenticateAsync(request, currentSettings.Auth0ServerUrl);

                    // set the authorization header
                    currentSettings.Auth0HeaderValue = new AuthenticationHeaderValue("Bearer", authToken.AccessToken);
                    currentSettings.LastRefresh = DateTimeOffset.Now;
                    logger.LogInformation($"Successfully authenticated with the service client id {currentSettings.Auth0ClientId} with client secret.");

                    ScheduleAutoRefresh(currentSettings);
                }
                catch (Exception ex)
                {
                    // any exceptions during authentication are logged here
                    logger.LogError($"Error authenticating with service: {currentSettings.Auth0ClientId} using user {currentSettings.Auth0Username}.", ex);
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
