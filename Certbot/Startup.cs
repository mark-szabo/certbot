using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
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
            // Add Configuration as a Singleton Service
            builder.Services.Configure<CertbotConfiguration>(Configuration);
            var config = Configuration.Get<CertbotConfiguration>();
            builder.Services.AddSingleton(config);

            // Add HttpClient
            builder.Services.AddHttpClient();

            // Add the DNS LookupClient as a Singleton Service
            builder.Services.AddSingleton(new LookupClient { UseCache = false, EnableAuditTrail = true });

            // Add the ACME protocol client factory as a Scoped Service
            builder.Services.AddScoped<IAcmeProtocolClientFactory, AcmeProtocolClientFactory>();

            // Add the KeyVaultClient as a Scoped Service
            builder.Services.AddScoped(_ =>
            {
                var tokenProvider = new AzureServiceTokenProvider();
                return new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback));
            });

            // Add the KeyVault SecretClient as a Scoped Service
            builder.Services.AddScoped(_ =>
            {
                var managedServiceIdentityCredential = new DefaultAzureCredential();
                return new SecretClient(new Uri(config.KeyVaultBaseUrl), managedServiceIdentityCredential);
            });

            // Add the KeyVault CertificateClient as a Scoped Service
            builder.Services.AddScoped(_ =>
            {
                var managedServiceIdentityCredential = new DefaultAzureCredential();
                return new CertificateClient(new Uri(config.KeyVaultBaseUrl), managedServiceIdentityCredential);
            });

            // Add the Azure API client as a Scoped Service
            builder.Services.AddScoped(_ =>
            {
                var tokenProvider = new AzureServiceTokenProvider();
                return Microsoft.Azure.Management.Fluent.Azure
                    .Configure()
                    .WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic)
                    .Authenticate(new AzureCredentials(
                        new TokenCredentials(tokenProvider.GetAccessTokenAsync("https://management.azure.com/", config.TenantId).Result),
                        new TokenCredentials(tokenProvider.GetAccessTokenAsync("https://graph.windows.net/", config.TenantId).Result),
                        config.TenantId,
                        AzureEnvironment.AzureGlobalCloud))
                    .WithSubscription(config.SubscriptionId);
            });

            // Add the BlobContainerClient as a Scoped Service
            builder.Services.AddScoped(_ =>
            {
                var managedServiceIdentityCredential = new DefaultAzureCredential();

                // Get a credential and create a client object for the blob container.
                var blobContainerClient = new BlobContainerClient(new Uri(config.BlobContainerUrl), managedServiceIdentityCredential);

                // Create the container if it does not exist.
                blobContainerClient.CreateIfNotExistsAsync(PublicAccessType.Blob).Wait();

                return blobContainerClient;
            });
        }
    }
}
