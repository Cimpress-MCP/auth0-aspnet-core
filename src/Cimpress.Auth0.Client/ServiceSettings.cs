using System;

namespace Cimpress.Auth0.Client
{
    /// <summary>
    /// A class that helps to define service settings from a service. It's related extension methods allow easy conversion to Auth0 settings.
    /// This helps to decouple the settings from the <see cref="Auth0ClientSettings"/>, which contain additional information such as the server URL,
    /// which can be shared between services and only needs a single setup at the Auth0TokenProvider.
    /// Additionally, some properties aren't relevant for Auth0, but are typically needed when configuring services, such as the base URI of the service to be called.
    /// </summary>
    public class ServiceSettings
    {
        /// <summary>
        /// The URI of the service to be called.
        /// </summary>
        public string Uri { get; set; }

        /// <summary>
        /// In case Basic Auth is used, it's password and user.
        /// </summary>
        public string BasicAuthPassword { get; set; }

        /// <summary>
        /// In case Basic Auth is used, it's password and user.
        /// </summary>
        public string BasicAuthUser { get; set; }

        /// <summary>
        /// The Auth0 user to use.
        /// </summary>
        public string Auth0User { get; set; }

        /// <summary>
        /// The Auth0 password to use.
        /// </summary>
        public string Auth0Password { get; set; }

        /// <summary>
        /// The Auth0 client Id.
        /// </summary>
        public string Auth0ClientId { get; set; }

        /// <summary>
        /// The Auth0 refresh token. If this is set, it will be used instead of Auth0User/Auth0Password.
        /// </summary>
        public string Auth0RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the time span after which the Bearer token should be refreshed.
        /// </summary>
        public TimeSpan AutoRefreshAfter { get; set; } = TimeSpan.MinValue;

        /// <summary>
        /// Gets or sets the client secret.
        /// </summary>
        public string Auth0ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the audience type.
        /// </summary>
        public string Auth0Audience { get; set; }
    }
}