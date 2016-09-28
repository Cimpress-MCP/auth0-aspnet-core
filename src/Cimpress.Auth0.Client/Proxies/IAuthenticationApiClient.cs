using System.Threading.Tasks;

namespace Cimpress.Auth0.Client.Proxies
{
    public interface IAuthenticationApiClient
    {
        /// <summary>
        /// Given an <see cref="RoAuthenticationRequestDto" />, it will do the authentication on the provider and return a <see cref="AuthenticationResponseDto" />
        /// </summary>
        /// <param name="request">The authentication request details containing information regarding the connection, username, password etc.</param>
        /// <param name="auth0Domain">The Auth0 domain to which to target the request to.</param>
        /// <returns>A <see cref="AuthenticationResponseDto" /> with the access token.</returns>
        Task<AuthenticationResponseDto> AuthenticateAsync(RoAuthenticationRequestDto request, string auth0Domain);

        /// <summary>
        /// Given an <see cref="TokenAuthenticationRequestDto" />, it will do the authentication on the provider and return a <see cref="AuthenticationResponseDto" />
        /// </summary>
        /// <param name="request">The authentication request details containing information regarding the connection, client secret etc.</param>
        /// <param name="auth0Domain">The Auth0 domain to which to target the request to.</param>
        /// <returns>A <see cref="AuthenticationResponseDto" /> with the access token.</returns>
        Task<AuthenticationResponseDto> TokenAuthenticateAsync(TokenAuthenticationRequestDto request, string auth0Domain);

        /// <summary>
        /// Given an existing token, this endpoint will generate a new token signed with the target client secret. This is used to flow the identity of the user from the application to an API or across different APIs that are protected with different secrets.
        /// </summary>
        /// <param name="request">The <see cref="DelegationRequestBaseDto" /> containing details about the request.</param>
        /// <param name="auth0Domain">The Auth0 domain to which to target the request to.</param>
        /// <returns>The <see cref="AccessToken" />.</returns>
        Task<AccessToken> GetDelegationTokenAsync(DelegationRequestBaseDto request, string auth0Domain);
    }
}