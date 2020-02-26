using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Certbot.Models;
using DnsClient;
using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Rest;
using System;

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

        public override void Configure(IFunctionsHostBuilder builder)
        {
            builder.Services.Configure<CertbotConfiguration>(Configuration);
            var config = Configuration.Get<CertbotConfiguration>();
            builder.Services.AddSingleton(config);

            AzureServiceTokenProvider tokenProvider = new AzureServiceTokenProvider();
            var managedServiceIdentityCredential = new DefaultAzureCredential(new DefaultAzureCredentialOptions { SharedTokenCacheUsername = "mark-ms@antavo.com" });

            builder.Services.AddHttpClient();

            builder.Services.AddSingleton(new LookupClient { UseCache = false, EnableAuditTrail = true });

            builder.Services.AddSingleton(provider =>
                new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback)));

            var secretClient = new SecretClient(new Uri(config.KeyVaultBaseUrl), managedServiceIdentityCredential);
            builder.Services.AddSingleton(secretClient);

            var certificateClient = new CertificateClient(new Uri(config.KeyVaultBaseUrl), managedServiceIdentityCredential);
            builder.Services.AddSingleton(certificateClient);

            var azure = Microsoft.Azure.Management.Fluent.Azure
                .Configure()
                .WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic)
                .Authenticate(new AzureCredentials(
                    new TokenCredentials(tokenProvider.GetAccessTokenAsync("https://management.azure.com/", config.TenantId).Result),
                    new TokenCredentials(tokenProvider.GetAccessTokenAsync("https://graph.windows.net/", config.TenantId).Result),
                    config.TenantId,
                    AzureEnvironment.AzureGlobalCloud))
                .WithSubscription(config.SubscriptionId);

            builder.Services.AddSingleton(azure);

            // Get a credential and create a client object for the blob container.
            var blobContainerClient = new BlobContainerClient(new Uri(config.BlobContainerUrl), managedServiceIdentityCredential);

            // Create the container if it does not exist.
            blobContainerClient.CreateIfNotExistsAsync(PublicAccessType.Blob).Wait();

            builder.Services.AddSingleton(blobContainerClient);

            builder.Services.AddSingleton<IAcmeProtocolClientFactory, AcmeProtocolClientFactory>();
        }
    }
}
