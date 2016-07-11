using System;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Cimpress.Auth0.Server
{
    public static class AuthenticationExtensions
    {
        private const string NonceProperty = "N";

        private static readonly string CookieStatePrefix = ".AspNetCore.Correlation.";

        private const string CorrelationProperty = ".xsrf";

        private static ILogger logger;

        private static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();

        public static void UseAuth0(this IServiceCollection services, string domain, string clientId, string clientSecret, Func<ClaimsIdentity, Task> onUserInformationReceived = null)
        {
            if (onUserInformationReceived == null)
            {
                onUserInformationReceived = _ => Task.FromResult(true);
            }
            
            services.Configure<OpenIdConnectOptions>(options =>
            {
                options.ClientId = clientId;
                options.ClientSecret = clientSecret;
                options.Authority = $"https://{domain}";
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.PostLogoutRedirectUri = "/";

                options.Events = new OpenIdConnectEvents()
                {
                    OnRedirectToIdentityProviderForSignOut = notification =>
                    {
                        logger.LogDebug("Signing out and redirecting to Auth0.");

                        notification.HandleResponse();
                        notification.HttpContext.Response.Redirect(
                            $"https://{domain}/v2/logout?returnTo={notification.ProtocolMessage.RedirectUri}");
                        return Task.FromResult(true);
                    },
                    OnMessageReceived = notification =>
                    {
                        logger.LogDebug("OpenID Connect message received.");
                        return Task.FromResult(true);
                    },
                    OnRedirectToIdentityProvider = notification =>
                    {
                        logger.LogDebug("Redirecting to Auth0.");
                        return Task.FromResult(true);
                    },
                    OnTicketReceived = notification =>
                    {
                        logger.LogDebug("Authentication ticket received.");
                        return Task.FromResult(true);
                    },
                    OnTokenResponseReceived = notification =>
                    {
                        logger.LogDebug("Token response received.");
                        return Task.FromResult(true);
                    },
                    OnAuthenticationFailed = notification =>
                    {
                        logger.LogError("Authentication failed: " + notification.Exception.Message);
                        return Task.FromResult(true);
                    },
                    OnAuthorizationCodeReceived = notification =>
                    {
                        logger.LogDebug("Authorization code received");
                        return Task.FromResult(true);
                    },
                    OnUserInformationReceived = notification =>
                    {
                        logger.LogDebug("Token validation received");
                        return Task.FromResult(true);
                    },
                    OnTokenValidated = async notification =>
                    {
                        var claimsIdentity = notification.Ticket.Principal.Identity as ClaimsIdentity;
                        logger.LogInformation($"{claimsIdentity?.Name} authenticated using bearer authentication.");

                        await onUserInformationReceived(claimsIdentity);
                    }
                };
            });
        }

        public static void UseAuth0(this IApplicationBuilder app)
        {
            var loggerFactory = (ILoggerFactory) app.ApplicationServices.GetService(typeof(ILoggerFactory));
            logger = loggerFactory.CreateLogger("Auth0");

            var options = app.ApplicationServices.GetRequiredService<IOptions<OpenIdConnectOptions>>();
            app.UseOpenIdConnectAuthentication(options.Value);
        }

        public static void SetJwtBearer(this IApplicationBuilder app, Auth0Settings settings, Func<ClaimsIdentity, Task> onTokenValidated)
        {
            var options = new JwtBearerOptions()
            {
                Audience = settings.ClientId,
                Authority = $"https://{settings.Domain}",
                Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        logger.LogDebug("Authentication failed.", context.Exception);
                        return Task.FromResult(0);
                    },
                    OnChallenge = context =>
                    {
                        logger.LogDebug("Bearer Auth OnChallenge.");
                        return Task.FromResult(true);
                    },
                    OnMessageReceived = context =>
                    {
                        logger.LogDebug("Bearer Auth OnMessageReceived");
                        return Task.FromResult(true);
                    },
                    OnTokenValidated = async context =>
                    {
                        var claimsIdentity = context.Ticket.Principal.Identity as ClaimsIdentity;
                        logger.LogInformation($"{claimsIdentity?.Name} authenticated using bearer authentication.");

                        await onTokenValidated(claimsIdentity);
                    }
                }
            };
            app.UseJwtBearerAuthentication(options);
            
            // this is a hack, which hopefully will be solved with RC2 of .net core
            // * The problem has been discussed here: https://github.com/aspnet/Security/issues/555
            // * The workaround got copied from here: https://github.com/aspnet-contrib/AspNet.Security.OpenIdConnect.Server/issues/191
            app.Use(next => async context =>
            {
                try
                {
                    await next(context);
                }
                catch (SecurityTokenException)
                {
                    // If the headers have already been sent, you can't replace the status code.
                    // In this case, throw an exception to close the connection.
                    if (context.Response.HasStarted)
                    {
                        throw;
                    }

                    context.Response.StatusCode = 401;
                }
            });

        }

        public static AuthenticationTransaction PrepareAuthentication(this HttpContext context, string callbackUrl, string returnUrl)
        {
            var middlewareOptions = context.RequestServices.GetRequiredService<IOptions<OpenIdConnectOptions>>().Value;
            var nonce = middlewareOptions.ProtocolValidator.GenerateNonce();

            // Add the nonce.
            context.Response.Cookies.Append(
                OpenIdConnectDefaults.CookieNoncePrefix + middlewareOptions.StringDataFormat.Protect(nonce),
                NonceProperty,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = context.Request.IsHttps,
                    Expires = DateTime.UtcNow + middlewareOptions.ProtocolValidator.NonceLifetime
                });

            // Prepare state.
            var authenticationProperties = new AuthenticationProperties() { RedirectUri = returnUrl };
            AddCallbackUrl(callbackUrl, authenticationProperties);
            GenerateCorrelationId(context, middlewareOptions, authenticationProperties);

            // Generate state.
            var state = Uri.EscapeDataString(middlewareOptions.StateDataFormat.Protect(authenticationProperties));

            // Return nonce to the Lock.
            return new AuthenticationTransaction(nonce, state);
        }

        private static void AddCallbackUrl(string callbackUrl, AuthenticationProperties properties)
        {
            properties.Items[OpenIdConnectDefaults.RedirectUriForCodePropertiesKey] = callbackUrl;
        }

        private static void GenerateCorrelationId(HttpContext context, OpenIdConnectOptions options, AuthenticationProperties properties)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            var bytes = new byte[32];
            CryptoRandom.GetBytes(bytes);
            var correlationId = Base64UrlTextEncoder.Encode(bytes);

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = context.Request.IsHttps,
                Expires = DateTime.UtcNow + options.ProtocolValidator.NonceLifetime
            };

            properties.Items[CorrelationProperty] = correlationId;

            var cookieName = CookieStatePrefix + OpenIdConnectDefaults.AuthenticationScheme + "." + correlationId;

            context.Response.Cookies.Append(cookieName, NonceProperty, cookieOptions);
        }

    }
}