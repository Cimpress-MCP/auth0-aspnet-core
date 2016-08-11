using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace Cimpress.Auth0.Client
{
    internal static class HttpResponseMessageExtensions
    {
        internal static async Task ThrowIfNotSuccessStatusCode(this HttpResponseMessage message)
        {
            if (!message.IsSuccessStatusCode)
            {
                var formattedMsg = await FormatErrorMessage(message);
                throw new Exception(formattedMsg);
            }
        }

        private static async Task<string> FormatErrorMessage(this HttpResponseMessage message)
        {
            var msg = await message.Content.ReadAsStringAsync();
            var formattedMsg = $"Error processing request. Status code was {message.StatusCode} when calling '{message.RequestMessage.RequestUri}', message was '{msg}'";
            return formattedMsg;
        }
    }
}
