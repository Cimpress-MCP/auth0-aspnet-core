using System;
using System.Threading.Tasks;
using Cimpress.Auth0.Client.Proxies;
using Xunit;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;

namespace Cimpress.Auth0.Client.UnitTests
{
    public class Auth0TokenProviderTests
    {
        private readonly Mock<ILoggerFactory> loggerFactor;
        private readonly Mock<ILogger> logger;
        private readonly Mock<IAutoScheduler> autoScheduler;

        public Auth0TokenProviderTests()
        {
            loggerFactor = new Mock<ILoggerFactory>(MockBehavior.Strict);
            logger = new Mock<ILogger>(MockBehavior.Loose);
            loggerFactor.Setup(lf => lf.CreateLogger(typeof(Auth0TokenProvider).FullName)).Returns(logger.Object);
            autoScheduler = new Mock<IAutoScheduler>(MockBehavior.Loose);
        }

        [Fact]
        public async Task Updates_with_refresh_token()
        {
            // setup
            var auth0serverUrl = "https://localhost";
            var apiClient = new Mock<IAuthenticationApiClient>(MockBehavior.Strict);
            RefreshTokenDelegationRequestDto delegationRequest = null;
            apiClient.Setup(ac => ac.GetDelegationTokenAsync(It.IsAny<RefreshTokenDelegationRequestDto>(), auth0serverUrl))
                .Callback((DelegationRequestBaseDto token, string server) => delegationRequest = token as RefreshTokenDelegationRequestDto)
                .Returns(Task.FromResult(new AccessToken { IdToken = Guid.NewGuid().ToString() }));
            var tokenProvider = new Auth0TokenProvider(loggerFactor.Object, new Auth0ClientSettings {Auth0ServerUrl = auth0serverUrl}, apiClient.Object, autoScheduler.Object);
            var auth0ClientSettings = new Auth0ClientSettings { Auth0ClientId = Guid.NewGuid().ToString(), Auth0RefreshToken = Guid.NewGuid().ToString() };

            // execute
            await tokenProvider.AddOrUpdateClientAsync(auth0ClientSettings);

            // validate
            apiClient.Verify(ac => ac.GetDelegationTokenAsync(It.IsAny<DelegationRequestBaseDto>(), auth0serverUrl), Times.Once);
            Assert.NotNull(delegationRequest);
            delegationRequest.RefreshToken.Should().Be(auth0ClientSettings.Auth0RefreshToken);
            delegationRequest.SourceClientId.Should().Be(auth0ClientSettings.Auth0ClientId);
            delegationRequest.TargetClientId.Should().Be(auth0ClientSettings.Auth0ClientId);
        }

        [Fact]
        public async Task Updates_with_username_and_password()
        {
            // setup
            var auth0serverUrl = "https://localhost";
            var auth0Connection = "unit-test-connection";
            var apiClient = new Mock<IAuthenticationApiClient>(MockBehavior.Strict);
            AuthenticationRequestDto authRequest = null;
            apiClient.Setup(ac => ac.AuthenticateAsync(It.IsAny<AuthenticationRequestDto>(), auth0serverUrl))
                .Callback((AuthenticationRequestDto token, string server) => authRequest = token)
                .Returns(Task.FromResult(new AuthenticationResponseDto { IdToken = Guid.NewGuid().ToString()}));
            var tokenProvider = new Auth0TokenProvider(loggerFactor.Object, new Auth0ClientSettings {Auth0ServerUrl = auth0serverUrl, Auth0Connection = auth0Connection}, apiClient.Object, autoScheduler.Object);
            var auth0ClientSettings = new Auth0ClientSettings {Auth0ClientId = Guid.NewGuid().ToString(), Auth0Username = Guid.NewGuid().ToString(), Auth0Password = Guid.NewGuid().ToString()};

            // execute
            await tokenProvider.AddOrUpdateClientAsync(auth0ClientSettings);

            // validate
            apiClient.Verify(ac => ac.AuthenticateAsync(It.IsAny<AuthenticationRequestDto>(), auth0serverUrl), Times.Once);
            Assert.NotNull(authRequest);
            authRequest.ClientId.Should().Be(auth0ClientSettings.Auth0ClientId);
            authRequest.Username.Should().Be(auth0ClientSettings.Auth0Username);
            authRequest.Password.Should().Be(auth0ClientSettings.Auth0Password);
            authRequest.Scope.Should().Be("openid");
            authRequest.Connection.Should().Be(auth0Connection);
            authRequest.GrantType.Should().Be("password");
            authRequest.Device.Should().Be("api");
        }

        [Fact]
        public async Task Does_not_reauthenticate_within_a_short_period_of_time_for_refresh_token()
        {
            // setup
            var apiClient = new Mock<IAuthenticationApiClient>(MockBehavior.Strict);
            apiClient.Setup(ac => ac.GetDelegationTokenAsync(It.IsAny<RefreshTokenDelegationRequestDto>(), It.IsAny<string>()))
                .Returns(Task.FromResult(new AccessToken { IdToken = Guid.NewGuid().ToString() }));
            var tokenProvider = new Auth0TokenProvider(loggerFactor.Object, new Auth0ClientSettings { Auth0ServerUrl = Guid.NewGuid().ToString() }, apiClient.Object, autoScheduler.Object);
            var auth0ClientSettings = new Auth0ClientSettings { Auth0ClientId = Guid.NewGuid().ToString(), Auth0RefreshToken = Guid.NewGuid().ToString() };

            // execute twice
            await tokenProvider.AddOrUpdateClientAsync(auth0ClientSettings);
            await tokenProvider.AddOrUpdateClientAsync(auth0ClientSettings);

            // validate that it was called only once
            apiClient.Verify(ac => ac.GetDelegationTokenAsync(It.IsAny<RefreshTokenDelegationRequestDto>(), It.IsAny<string>()), Times.Once);
        }

        [Fact]
        public async Task Reauthenticate_within_a_short_period_of_time_when_forced_for_refresh_token()
        {
            // setup
            var apiClient = new Mock<IAuthenticationApiClient>(MockBehavior.Strict);
            apiClient.Setup(ac => ac.GetDelegationTokenAsync(It.IsAny<RefreshTokenDelegationRequestDto>(), It.IsAny<string>()))
                .Returns(Task.FromResult(new AccessToken { IdToken = Guid.NewGuid().ToString()}));
            var tokenProvider = new Auth0TokenProvider(loggerFactor.Object, new Auth0ClientSettings { Auth0ServerUrl = Guid.NewGuid().ToString() }, apiClient.Object, autoScheduler.Object);
            var auth0ClientSettings = new Auth0ClientSettings { Auth0ClientId = Guid.NewGuid().ToString(), Auth0RefreshToken = Guid.NewGuid().ToString() };

            // execute twice
            await tokenProvider.AddOrUpdateClientAsync(auth0ClientSettings);
            await tokenProvider.AddOrUpdateClientAsync(auth0ClientSettings, true);

            // validate that it was called only once
            apiClient.Verify(ac => ac.GetDelegationTokenAsync(It.IsAny<RefreshTokenDelegationRequestDto>(), It.IsAny<string>()), Times.Exactly(2));
        }

        [Fact]
        public async Task Does_not_reauthenticate_within_a_short_period_of_time_for_username_password()
        {
            // setup
            var apiClient = new Mock<IAuthenticationApiClient>(MockBehavior.Strict);
            apiClient.Setup(ac => ac.AuthenticateAsync(It.IsAny<AuthenticationRequestDto>(), It.IsAny<string>()))
                 .Returns(Task.FromResult(new AuthenticationResponseDto { IdToken = Guid.NewGuid().ToString() }));
            var tokenProvider = new Auth0TokenProvider(loggerFactor.Object, new Auth0ClientSettings { Auth0ServerUrl = Guid.NewGuid().ToString() }, apiClient.Object, autoScheduler.Object);
            var auth0ClientSettings = new Auth0ClientSettings { Auth0ClientId = Guid.NewGuid().ToString(), Auth0Username = Guid.NewGuid().ToString(), Auth0Password = Guid.NewGuid().ToString() };

            // execute twice
            await tokenProvider.AddOrUpdateClientAsync(auth0ClientSettings);
            await tokenProvider.AddOrUpdateClientAsync(auth0ClientSettings);

            // validate that it was called only once
            apiClient.Verify(ac => ac.AuthenticateAsync(It.IsAny<AuthenticationRequestDto>(), It.IsAny<string>()), Times.Once);
        }

        [Fact]
        public async Task Reauthenticate_within_a_short_period_of_time_when_forced_for_username_password()
        {
            // setup
            var apiClient = new Mock<IAuthenticationApiClient>(MockBehavior.Strict);
            apiClient.Setup(ac => ac.AuthenticateAsync(It.IsAny<AuthenticationRequestDto>(), It.IsAny<string>()))
                 .Returns(Task.FromResult(new AuthenticationResponseDto { IdToken = Guid.NewGuid().ToString() }));
            var tokenProvider = new Auth0TokenProvider(loggerFactor.Object, new Auth0ClientSettings { Auth0ServerUrl = Guid.NewGuid().ToString() }, apiClient.Object, autoScheduler.Object);
            var auth0ClientSettings = new Auth0ClientSettings { Auth0ClientId = Guid.NewGuid().ToString(), Auth0Username = Guid.NewGuid().ToString(), Auth0Password = Guid.NewGuid().ToString() };

            // execute twice
            await tokenProvider.AddOrUpdateClientAsync(auth0ClientSettings);
            await tokenProvider.AddOrUpdateClientAsync(auth0ClientSettings, true);

            // validate that it was called only once
            apiClient.Verify(ac => ac.AuthenticateAsync(It.IsAny<AuthenticationRequestDto>(), It.IsAny<string>()), Times.Exactly(2));
        }

        [Fact]
        public async Task Schedules_auto_refresh_for_username_password()
        {
            // setup
            var apiClient = new Mock<IAuthenticationApiClient>(MockBehavior.Strict);
            apiClient.Setup(ac => ac.AuthenticateAsync(It.IsAny<AuthenticationRequestDto>(), It.IsAny<string>()))
                 .Returns(Task.FromResult(new AuthenticationResponseDto { IdToken = Guid.NewGuid().ToString() }));
            var scheduler = new Mock<IAutoScheduler>(MockBehavior.Strict);
            scheduler.Setup(s => s.ScheduleRefresh(It.IsAny<Auth0ClientSettings>()));
            var tokenProvider = new Auth0TokenProvider(loggerFactor.Object, new Auth0ClientSettings { Auth0ServerUrl = Guid.NewGuid().ToString() }, apiClient.Object, scheduler.Object);
            var auth0ClientSettings = new Auth0ClientSettings { Auth0ClientId = Guid.NewGuid().ToString(), Auth0Username = Guid.NewGuid().ToString(), Auth0Password = Guid.NewGuid().ToString() };

            // execute twice
            await tokenProvider.AddOrUpdateClientAsync(auth0ClientSettings);

            // validate that it was called only once
            scheduler.Verify(ac => ac.ScheduleRefresh(It.IsAny<Auth0ClientSettings>()), Times.Once);
        }

        [Fact]
        public async Task Schedules_auto_refresh_for_refresh_token()
        {
            // setup
            var apiClient = new Mock<IAuthenticationApiClient>(MockBehavior.Strict);
            apiClient.Setup(ac => ac.GetDelegationTokenAsync(It.IsAny<RefreshTokenDelegationRequestDto>(), It.IsAny<string>()))
                .Returns(Task.FromResult(new AccessToken { IdToken = Guid.NewGuid().ToString() }));
            var scheduler = new Mock<IAutoScheduler>(MockBehavior.Strict);
            scheduler.Setup(s => s.ScheduleRefresh(It.IsAny<Auth0ClientSettings>()));
            var tokenProvider = new Auth0TokenProvider(loggerFactor.Object, new Auth0ClientSettings { Auth0ServerUrl = Guid.NewGuid().ToString() }, apiClient.Object, scheduler.Object);
            var auth0ClientSettings = new Auth0ClientSettings { Auth0ClientId = Guid.NewGuid().ToString(), Auth0RefreshToken = Guid.NewGuid().ToString() };

            // execute twice
            await tokenProvider.AddOrUpdateClientAsync(auth0ClientSettings);

            // validate that it was called only once
            scheduler.Verify(ac => ac.ScheduleRefresh(It.IsAny<Auth0ClientSettings>()), Times.Once);
        }
    }
}