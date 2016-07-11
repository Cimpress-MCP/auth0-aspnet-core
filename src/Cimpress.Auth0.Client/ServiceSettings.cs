namespace Cimpress.Auth0.Client
{
    public class ServiceSettings
    {
        public string Uri { get; set; }
        public string BasicAuthPassword { get; set; }
        public string BasicAuthUser { get; set; }
        public string Auth0User { get; set; }
        public string Auth0Password { get; set; }
        public string Auth0ClientId { get; set; }
        public string Auth0RefreshToken { get; set; }
    }
}