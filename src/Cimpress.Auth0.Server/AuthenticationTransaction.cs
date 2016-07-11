namespace Cimpress.Auth0.Server
{
    public class AuthenticationTransaction
    {
        public string Nonce { get; }

        public string State { get; }

        public AuthenticationTransaction(string nonce, string state)
        {
            Nonce = nonce;
            State = state;
        }
    }
}