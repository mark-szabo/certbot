using DnsClient;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Management.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Rest;

[assembly: FunctionsStartup(typeof(Certbot.Startup))]

namespace Certbot
{
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            AzureServiceTokenProvider tokenProvider = new AzureServiceTokenProvider();

            builder.Services.AddHttpClient();

            builder.Services.AddSingleton(new LookupClient { UseCache = false, EnableAuditTrail = true });

            builder.Services.AddSingleton(provider =>
                new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback)));

            string tenantId = "ec2490be-5e17-49e0-8489-f93d6e6ad876";
            string subscriptionId = "70dd28be-ad6c-4827-98d7-e9624ff5ee69";

            var azure = Azure
                .Configure()
                .WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic)
                .Authenticate(new AzureCredentials(
                    new TokenCredentials(tokenProvider.GetAccessTokenAsync("https://management.azure.com/").Result),
                    new TokenCredentials(tokenProvider.GetAccessTokenAsync("https://graph.windows.net/").Result),
                    tenantId,
                    AzureEnvironment.AzureGlobalCloud))
                .WithSubscription(subscriptionId);

            builder.Services.AddSingleton(azure);
        }
    }
}
