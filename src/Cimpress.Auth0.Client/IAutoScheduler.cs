namespace Cimpress.Auth0.Client
{
    /// <summary>
    /// Allows to auto-schedule the refresh token.
    /// </summary>
    public interface IAutoScheduler
    {
        /// <summary>
        /// Triggers 
        /// </summary>
        /// <param name="auth0ClientSettings"></param>
        void ScheduleRefresh(Auth0ClientSettings auth0ClientSettings);
    }
}