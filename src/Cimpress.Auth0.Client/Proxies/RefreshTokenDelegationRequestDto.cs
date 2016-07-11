using Newtonsoft.Json;

namespace Cimpress.Auth0.Client.Proxies
{
    /// <summary>
    /// 
    /// </summary>
    /// <remarks>
    /// This has been copied and slightly adapterd from https://github.com/auth0/auth0.net since it doesn't yet support netcore.
    /// </remarks>
    public class RefreshTokenDelegationRequestDto : DelegationRequestBaseDto
    {
        /// <summary>
        /// The current RefreshToken to update.
        /// </summary>
        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="sourceClientId"></param>
        /// <param name="targetClientId"></param>
        /// <param name="refreshToken"></param>
        public RefreshTokenDelegationRequestDto(string sourceClientId, string targetClientId, string refreshToken) : base(sourceClientId, targetClientId)
        {
            RefreshToken = refreshToken;
        }
    }
}