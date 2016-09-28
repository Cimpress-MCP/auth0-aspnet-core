using Newtonsoft.Json;

namespace Cimpress.Auth0.Client.Proxies
{
    /// <summary>
    /// Represents a request to authenticate with a connection.
    /// </summary>
    /// <remarks>
    /// This has been copied and slightly adapterd from https://github.com/auth0/auth0.net since it doesn't yet support netcore.
    /// </remarks>
    public class TokenAuthenticationRequestDto
    {
        /// <summary>
        /// Gets or sets the client (app) identifier.
        /// </summary>
        [JsonProperty("client_id")]
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client (app) secret.
        /// </summary>
        [JsonProperty("client_secret")]
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the grant type requested.
        /// </summary>
        [JsonProperty("grant_type")]
        public string GrantType { get; set; }
        
        /// <summary>
        /// Gets or sets the audience.
        /// </summary>
        [JsonProperty("audience")]
        public string Audience { get; set; }
    }
}