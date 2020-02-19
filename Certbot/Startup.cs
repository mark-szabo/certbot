using Certbot.Models;
using DnsClient;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Management.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Rest;

[assembly: FunctionsStartup(typeof(Certbot.Startup))]

namespace Certbot
{
    public class Startup : FunctionsStartup
    {
        public Startup()
        {
            Configuration = new ConfigurationBuilder()
                .AddEnvironmentVariables()
                .Build();
        }

        public IConfiguration Configuration { get; }

        public override async System.Threading.Tasks.Task ConfigureAsync(IFunctionsHostBuilder builder)
        {
            builder.Services.Configure<CertbotConfiguration>(Configuration);
            var config = Configuration.Get<CertbotConfiguration>();
            builder.Services.AddSingleton(config);


            AzureServiceTokenProvider tokenProvider = new AzureServiceTokenProvider();

            builder.Services.AddHttpClient();

            builder.Services.AddSingleton(new LookupClient { UseCache = false, EnableAuditTrail = true });

            builder.Services.AddSingleton(provider =>
                new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback)));

            var azure = Azure
                .Configure()
                .WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic)
                .Authenticate(new AzureCredentials(
                    new TokenCredentials(tokenProvider.GetAccessTokenAsync("https://management.azure.com/").Result),
                    new TokenCredentials(tokenProvider.GetAccessTokenAsync("https://graph.windows.net/").Result),
                    config.TenantId,
                    AzureEnvironment.AzureGlobalCloud))
                .WithSubscription(config.SubscriptionId);

            builder.Services.AddSingleton(azure);
        }
    }
}
