using Newtonsoft.Json;

namespace Cimpress.Auth0.Client.Proxies
{
    /// <summary>
    /// Represents an access token.
    /// </summary>
    /// <remarks>
    /// This has been copied and slightly adapterd from https://github.com/auth0/auth0.net since it doesn't yet support netcore.
    /// </remarks>
    public class AccessToken : TokenBaseDto
    {
        /// <summary>
        /// Gets or sets the identifier token.
        /// </summary>
        [JsonProperty("id_token")]
        public string IdToken { get; set; }

        /// <summary>
        /// Gets or sets the expiry time in seconds.
        /// </summary>
        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }
    }
}