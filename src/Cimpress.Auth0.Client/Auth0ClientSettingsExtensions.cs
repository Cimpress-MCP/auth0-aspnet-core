namespace Cimpress.Auth0.Client
{
    public static class Auth0ClientSettingsExtensions
    {
        public static Auth0ClientSettings ToAuth0ClientSettings(this ServiceSettings serviceSettings)
        {
            return new Auth0ClientSettings()
            {
                Auth0ClientId = serviceSettings.Auth0ClientId,
                Auth0RefreshToken = serviceSettings.Auth0RefreshToken,
                Auth0Password = serviceSettings.Auth0Password,
                Auth0Username = serviceSettings.Auth0User
            };
        }
    }
}
