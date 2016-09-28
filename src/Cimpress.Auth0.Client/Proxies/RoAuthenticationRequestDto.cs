using Newtonsoft.Json;

namespace Cimpress.Auth0.Client.Proxies
{
    /// <summary>
    /// Represents a request to authenticate with a connection.
    /// </summary>
    /// <remarks>
    /// This has been copied and slightly adapterd from https://github.com/auth0/auth0.net since it doesn't yet support netcore.
    /// </remarks>
    public class RoAuthenticationRequestDto
    {
        /// <summary>
        /// Gets or sets the client (app) identifier.
        /// </summary>
        [JsonProperty("client_id")]
        public string ClientId { get; set; }
        
        /// <summary>
        /// Gets or sets the connection.
        /// </summary>
        [JsonProperty("connection")]
        public string Connection { get; set; }

        /// <summary>
        /// Gets or sets the device.
        /// </summary>
        [JsonProperty("device")]
        public string Device { get; set; }

        /// <summary>
        /// Gets or sets the grant type requested.
        /// </summary>
        [JsonProperty("grant_type")]
        public string GrantType { get; set; }

        /// <summary>
        /// Gets or sets the identifier token.
        /// </summary>
        [JsonProperty("id_token")]
        public string IdToken { get; set; }

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        [JsonProperty("password")]
        public string Password { get; set; }

        /// <summary>
        /// Gets or sets the requested scope.
        /// </summary>
        [JsonProperty("scope")]
        public string Scope { get; set; }

        /// <summary>
        /// Gets or sets the username.
        /// </summary>
        [JsonProperty("username")]
        public string Username { get; set; }
    }
}