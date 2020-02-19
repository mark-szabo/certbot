using ACMESharp.Protocol;
using Certbot.Models;
using System;
using System.Threading.Tasks;

namespace Certbot
{
    public interface IAcmeProtocolClientFactory
    {
        Task<AcmeProtocolClient> CreateClientAsync();
    }

    internal class AcmeProtocolClientFactory : IAcmeProtocolClientFactory
    {
        private readonly CertbotConfiguration _configuration;
        private readonly Uri _acmeEndpoint;

        public AcmeProtocolClientFactory(CertbotConfiguration configuration)
        {
            _configuration = configuration;
            _acmeEndpoint = new Uri(configuration.AcmeEndpoint);
        }

        public async Task<AcmeProtocolClient> CreateClientAsync()
        {
            var acmeProtocolClient = new AcmeProtocolClient(_acmeEndpoint);

            var directory = await acmeProtocolClient.GetDirectoryAsync();
            acmeProtocolClient.Directory = directory;

            await acmeProtocolClient.GetNonceAsync();

            var account = await acmeProtocolClient.CreateAccountAsync(new[] { "mailto:" + _configuration.AcmeAccountEmail }, true);
            acmeProtocolClient.Account = account;

            return acmeProtocolClient;
        }
    }
}
