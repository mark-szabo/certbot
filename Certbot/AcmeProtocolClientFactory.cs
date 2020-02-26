using ACMESharp.Protocol;
using Azure.Security.KeyVault.Secrets;
using Certbot.Models;
using Newtonsoft.Json;
using System;
using System.Threading.Tasks;

namespace Certbot
{
    public interface IAcmeProtocolClientFactory
    {
        Task<AcmeProtocolClient> CreateClientAsync();
    }

    public class AcmeProtocolClientFactory : IAcmeProtocolClientFactory
    {
        private const string ACME_ACCOUNT_NAME = "acme-account";
        private const string ACME_ACCOUNT_KEY_NAME = "acme-account-key";
        private readonly CertbotConfiguration _configuration;
        private readonly Uri _acmeEndpoint;
        private readonly SecretClient _secretClient;

        public AcmeProtocolClientFactory(CertbotConfiguration configuration, SecretClient secretClient)
        {
            _configuration = configuration;
            _acmeEndpoint = new Uri(configuration.AcmeEndpoint);
            _secretClient = secretClient;
        }

        public async Task<AcmeProtocolClient> CreateClientAsync()
        {
            var account = await LoadStateAsync<AccountDetails>(ACME_ACCOUNT_NAME);
            var accountKey = await LoadStateAsync<AccountKey>(ACME_ACCOUNT_KEY_NAME);

            var acmeProtocolClient = new AcmeProtocolClient(_acmeEndpoint, null, account, accountKey?.GenerateSigner());

            var directory = await acmeProtocolClient.GetDirectoryAsync();
            acmeProtocolClient.Directory = directory;

            await acmeProtocolClient.GetNonceAsync();

            if (acmeProtocolClient.Account == null)
            {
                account = await acmeProtocolClient.CreateAccountAsync(new[] { "mailto:" + _configuration.AcmeAccountEmail }, true);
                acmeProtocolClient.Account = account;

                accountKey = new AccountKey
                {
                    KeyType = acmeProtocolClient.Signer.JwsAlg,
                    KeyExport = acmeProtocolClient.Signer.Export()
                };

                await SaveStateAsync(ACME_ACCOUNT_NAME, account);
                await SaveStateAsync(ACME_ACCOUNT_KEY_NAME, accountKey);
            }

            return acmeProtocolClient;
        }
        private async Task<T> LoadStateAsync<T>(string name)
        {
            try
            {
                var secret = await _secretClient.GetSecretAsync(name);

                return JsonConvert.DeserializeObject<T>(secret.Value.Value);
            }
            catch (Azure.RequestFailedException)
            {
                return default;
            }
        }

        private async Task SaveStateAsync<T>(string name, T value)
        {
            var json = JsonConvert.SerializeObject(value);

            await _secretClient.SetSecretAsync(name, json);
        }
    }
}
