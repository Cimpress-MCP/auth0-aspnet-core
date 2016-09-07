using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Cimpress.Auth0.Client
{
    internal class AutoScheduler : IAutoScheduler
    {
        private readonly IAuth0TokenProvider tokenProvider;
        private readonly ILogger<AutoScheduler> logger;
        private readonly IDictionary<string, Timer> triggers;
        private readonly object syncObj = new object();

        public AutoScheduler(ILoggerFactory loggerFactory, IAuth0TokenProvider tokenProvider)
        {
            this.tokenProvider = tokenProvider;
            logger = loggerFactory.CreateLogger<AutoScheduler>();
            triggers = new Dictionary<string, Timer>();
        }

        public void ScheduleRefresh(Auth0ClientSettings auth0ClientSettings)
        {
            // do not auto-refresh 
            if (auth0ClientSettings.AutoRefreshAfter <= TimeSpan.Zero)
            {
                logger.LogDebug($"Not scheduling an automatic refresh of the Bearer token for client_id {auth0ClientSettings.Auth0ClientId} " +
                                $"and auto-refresh settings {auth0ClientSettings.AutoRefreshAfter}.");
                return;
            }

            lock (syncObj)
            {
                // add timer is it doesn't exist for the given client id
                if (!triggers.ContainsKey(auth0ClientSettings.Auth0ClientId))
                {
                    triggers.Add(auth0ClientSettings.Auth0ClientId,
                        new Timer(state => ExecuteRefresh((Auth0ClientSettings) state), auth0ClientSettings, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan));
                }

                // trigger refresh after given time
                triggers[auth0ClientSettings.Auth0ClientId].Change(auth0ClientSettings.AutoRefreshAfter, Timeout.InfiniteTimeSpan);
            }
        }

        private void ExecuteRefresh(Auth0ClientSettings auth0ClientSettings)
        {
            // log that we're refreshing
            logger.LogInformation($"Scheduling an automatic refresh of the Bearer token for client_id {auth0ClientSettings.Auth0ClientId} in {auth0ClientSettings.AutoRefreshAfter}.");

            // trigger the actual refresh
            var task = tokenProvider.AddOrUpdateClientAsync(auth0ClientSettings.Auth0ClientId);

            // log error cases
            task.ContinueWith(t => logger.LogError(0, t.Exception, $"Error while refreshing the Bearer token for client_id {auth0ClientSettings.Auth0ClientId}."), TaskContinuationOptions.OnlyOnFaulted);
        }
    }
}