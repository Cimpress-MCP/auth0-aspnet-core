using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Cimpress.Auth0.Client
{
    public static class HttpResponseMessageExtensions
    {
        internal static async Task LogAndThrowIfNotSuccessStatusCode(this HttpResponseMessage message, ILogger logger)
        {
            if (!message.IsSuccessStatusCode)
            {
                var formattedMsg = await message.LogMessage(logger);
                throw new Exception(formattedMsg);
            }
        }

        private static async Task<string> LogMessage(this HttpResponseMessage message, ILogger logger)
        {
            var msg = await message.Content.ReadAsStringAsync();
            var formattedMsg =
                $"Error processing request. Status code was {message.StatusCode} when calling '{message.RequestMessage.RequestUri}', message was '{msg}'";
            logger.LogError(formattedMsg);
            return formattedMsg;
        }
    }
}
