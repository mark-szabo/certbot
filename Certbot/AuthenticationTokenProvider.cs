using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Rest;

namespace Certbot
{
    internal class AuthenticationTokenProvider : ITokenProvider
    {
        private readonly AzureServiceTokenProvider _tokenProvider = new AzureServiceTokenProvider();

        public async Task<AuthenticationHeaderValue> GetAuthenticationHeaderAsync(CancellationToken cancellationToken)
        {
            var accessToken = await _tokenProvider.GetAccessTokenAsync("https://management.azure.com/");

            return new AuthenticationHeaderValue("Bearer", accessToken);
        }
    }
}
