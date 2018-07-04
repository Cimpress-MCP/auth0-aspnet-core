using System;
using System.Net.Http.Headers;

namespace Cimpress.Auth0.Client
{
    /// <summary>
    /// Class representing the settings required to acquire an Auth0 token.
    /// </summary>
    public class Auth0ClientSettings
    {
        /// <summary>
        /// Gets or sets the Auth0 server connection.
        /// </summary>
        /// <value>
        /// The Auth0 server connection.
        /// </value>
        public string Auth0Connection { get; set; }

        /// <summary>
        /// Gets or sets the Auth0 server Url.
        /// </summary>
        /// <value>
        /// The Auth0 server url of the Auth0 token provider.
        /// </value>
        public string Auth0ServerUrl { get; set; }

        /// <summary>
        /// Gets or sets the client identifier.
        /// </summary>
        /// <value>
        /// The client identifier.
        /// </value>
        public string Auth0ClientId { get; set; }

        /// <summary>
        /// Gets or sets the auth0 username.
        /// </summary>
        /// <value>
        /// The auth0 username.
        /// </value>
        public string Auth0Username { get; set; }

        /// <summary>
        /// Gets or sets the auth0 password.
        /// </summary>
        /// <value>
        /// The auth0 password.
        /// </value>
        public string Auth0Password { get; set; }

        //the black dog institute
        /// <summary>
        /// Gets or sets the client secret.
        /// </summary>
        /// <value>
        /// The client secret (replaces a password). 
        /// </value>
        public string Auth0ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the audience.
        /// </summary>
        /// <value>
        /// The audience domain.
        /// </value>
        public string Auth0Audience { get; set; }
        
        /// <summary>
        /// Gets or sets the realm.
        /// </summary>
        /// <value>
        /// The realm used for token authentication.
        /// </value>
        public string Auth0Realm { get; set; }
        
        /// <summary>
        /// Gets or sets the grant type.
        /// </summary>
        /// <value>
        /// The grant type used for token authentication.
        /// </value>
        public string Auth0GrantType { get; set; }

        /// <summary>
        /// Gets or sets the auth0 refresh token.
        /// </summary>
        /// <value>
        /// The auth0 refresh token.
        /// </value>
        public string Auth0RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the auth0 header value.
        /// </summary>
        /// <value>
        /// The auth0 header value.
        /// </value>
        public AuthenticationHeaderValue Auth0HeaderValue { get; set; }

        /// <summary>
        /// Gets or sets the last refresh time.
        /// </summary>
        /// <value>
        /// The last time the token was refreshed.
        /// </value>
        public DateTimeOffset LastRefresh { get; set; }

        /// <summary>
        /// Gets or sets the time span after which the Bearer token should be refreshed.
        /// </summary>
        /// <value>
        /// The time span after which the token should be automatically refreshed. Must be larger than TimeSpan.Zero to trigger a refresh.
        /// </value>
        public TimeSpan AutoRefreshAfter { get; set; } = TimeSpan.MinValue;
    }
}
