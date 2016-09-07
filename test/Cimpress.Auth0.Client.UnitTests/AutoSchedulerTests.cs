using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;

namespace Cimpress.Auth0.Client.UnitTests
{
    public class AutoSchedulerTests
    {
        private readonly Mock<ILoggerFactory> loggerFactory;
        private readonly Mock<ILogger> logger;

        public AutoSchedulerTests()
        {
            loggerFactory = new Mock<ILoggerFactory>(MockBehavior.Strict);
            logger = new Mock<ILogger>(MockBehavior.Loose);
            loggerFactory.Setup(lf => lf.CreateLogger(typeof(AutoScheduler).FullName)).Returns(logger.Object);
        }

        [Fact]
        public void Triggers_refresh_when_auto_scheduling()
        {
            // setup
            var resetEvent = new ManualResetEvent(false);
            var clientSettings = new Auth0ClientSettings {Auth0ClientId = Guid.NewGuid().ToString(), AutoRefreshAfter = TimeSpan.FromTicks(1)};
            var tokenProvider = new Mock<IAuth0TokenProvider>(MockBehavior.Strict);
            tokenProvider.Setup(tp => tp.AddOrUpdateClientAsync(clientSettings.Auth0ClientId, false)).Callback(() => resetEvent.Set()).Returns(Task.FromResult(true));
            var scheduler = new AutoScheduler(loggerFactory.Object, tokenProvider.Object);

            // execute
            scheduler.ScheduleRefresh(clientSettings);

            // validate
            resetEvent.WaitOne(TimeSpan.FromSeconds(10));
            tokenProvider.Verify(tp => tp.AddOrUpdateClientAsync(clientSettings.Auth0ClientId, false), Times.Once);
        }
    }
}