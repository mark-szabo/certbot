using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Certbot.Models;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Management.Fluent;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.DurableTask;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Extensions.Logging;

namespace Certbot
{
    public class RenewCertificatesFunctions
    {
        private readonly CertbotConfiguration _configuration;
        private readonly KeyVaultClient _keyVaultClient;
        private readonly IAzure _azure;

        public RenewCertificatesFunctions(CertbotConfiguration configuration, KeyVaultClient keyVaultClient, IAzure azure)
        {
            _configuration = configuration;
            _keyVaultClient = keyVaultClient;
            _azure = azure;
        }

        [FunctionName("RenewCertificatesFunctions_Trigger")]
        public async Task Trigger(
            [TimerTrigger("0 0 0 * * *", RunOnStartup = true)] TimerInfo timer,
            [DurableClient] IDurableOrchestrationClient starter,
            ILogger log)
        {
            string instanceId = await starter.StartNewAsync("RenewCertificatesFunctions", null);

            log.LogInformation($"Started orchestration with ID = '{instanceId}'.");
        }

        [FunctionName("RenewCertificatesFunctions")]
        public async Task RunOrchestrator([OrchestrationTrigger] IDurableOrchestrationContext context)
        {
            var hostnames = await context.CallActivityAsync<List<string>>(nameof(GetExpiringCertificatesFromApplicationGatewayAsync), null);

            await context.CallSubOrchestratorAsync("AddMultipleCertificatesFunctions", hostnames);
        }

        /// <summary>
        /// Get expiring certificates from Application Gateway.
        /// </summary>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(GetExpiringCertificatesFromApplicationGatewayAsync))]
        public async Task<List<string>> GetExpiringCertificatesFromApplicationGatewayAsync([ActivityTrigger] object input, ILogger log)
        {
            log.LogInformation("Getting expiring certificates from Application Gateway.");
            var expiringCertificateHostnames = new List<string>();

            var applicationGateway = await _azure.ApplicationGateways.GetByResourceGroupAsync(_configuration.ApplicationGatewayResourceGroup, _configuration.ApplicationGatewayName);
            var keyVaultSecretIds = applicationGateway.SslCertificates.Values.Select(cert => cert.KeyVaultSecretId);

            keyVaultSecretIds.ToList().ForEach(async secretId =>
            {
                var secret = await _keyVaultClient.GetSecretAsync(secretId);
                var hostname = secret.Tags["Hostname"];

                if (secret.Attributes.Expires < DateTime.Today.AddDays(14) && hostname != null)
                {
                    expiringCertificateHostnames.Add(hostname);
                }
            });

            return expiringCertificateHostnames;
        }
    }
}