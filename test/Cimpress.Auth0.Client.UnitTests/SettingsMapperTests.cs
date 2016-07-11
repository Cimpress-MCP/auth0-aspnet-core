using Xunit;
using FluentAssertions;

namespace Cimpress.Auth0.Client.UnitTests
{
    public class SettingsMapperTests
    {
        [Fact]
        public void SettingsMapper_when_mapping_UsernamePassword()
        {
            var clientSettings = new ServiceSettings()
            {
                Auth0ClientId = "auth0ClientId",
                Auth0Password = "auth0Password",
                Auth0User = "auth0User"
            };
            var auth0Settings = clientSettings.ToAuth0ClientSettings();
            clientSettings.Auth0ClientId.Should().Be(auth0Settings.Auth0ClientId);
            clientSettings.Auth0Password.Should().Be(auth0Settings.Auth0Password);
            clientSettings.Auth0User.Should().Be(auth0Settings.Auth0Username);
        }

        [Fact]
        public void SettingsMapper_when_mapping_RefreshToken()
        {
            var clientSettings = new ServiceSettings()
            {
                Auth0ClientId = "auth0ClientId",
                Auth0RefreshToken = "auth0RefreshToken"
            };
            var auth0Settings = clientSettings.ToAuth0ClientSettings();
            clientSettings.Auth0ClientId.Should().Be(auth0Settings.Auth0ClientId);
            clientSettings.Auth0RefreshToken.Should().Be(auth0Settings.Auth0RefreshToken);
        }
    }
}

