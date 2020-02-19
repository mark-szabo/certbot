using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Certbot.Models;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Rest;

namespace Certbot
{
    internal class AuthenticationTokenProvider : ITokenProvider
    {
        private readonly AzureServiceTokenProvider _tokenProvider = new AzureServiceTokenProvider();
        private readonly CertbotConfiguration _configuration;

        public AuthenticationTokenProvider(CertbotConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task<AuthenticationHeaderValue> GetAuthenticationHeaderAsync(CancellationToken cancellationToken)
        {
            var accessToken = await _tokenProvider.GetAccessTokenAsync("https://management.azure.com/", _configuration.TenantId);

            return new AuthenticationHeaderValue("Bearer", accessToken);
        }
    }
}
