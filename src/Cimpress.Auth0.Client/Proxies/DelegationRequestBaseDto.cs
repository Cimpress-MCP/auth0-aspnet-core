using Newtonsoft.Json;

namespace Cimpress.Auth0.Client.Proxies
{
    /// <summary>
    /// 
    /// </summary>
    /// <remarks>
    /// This has been copied and slightly adapterd from https://github.com/auth0/auth0.net since it doesn't yet support netcore.
    /// </remarks>
    public abstract class DelegationRequestBaseDto
    {
        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("api_type")]
        string ApiType { get; set; }

        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("grant_type")]
        public string GrantType { get; set; }

        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("scope")]
        public string Scope { get; set; }

        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("client_id")]
        public string SourceClientId { get; set; }

        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("target")]
        public string TargetClientId { get; set; }
        
        /// <summary>
        /// 
        /// </summary>
        protected DelegationRequestBaseDto()
        {
            GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
            Scope = "openid";
            ApiType = "app";
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sourceClientId"></param>
        /// <param name="targetClientId"></param>
        protected DelegationRequestBaseDto(string sourceClientId, string targetClientId) : this()
        {
            SourceClientId = sourceClientId;
            TargetClientId = targetClientId;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sourceClientId"></param>
        /// <param name="targetClientId"></param>
        /// <param name="apiType"></param>
        protected DelegationRequestBaseDto(string sourceClientId, string targetClientId, string apiType) : this(sourceClientId, targetClientId)
        {
            ApiType = apiType;
        }
    }
}