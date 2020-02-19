using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Certbot.Models;
using DnsClient;
using DnsClient.Protocol;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Management.Fluent;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.DurableTask;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Certbot
{
    public class AddCertificateFunctions
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly CertbotConfiguration _configuration;
        private readonly LookupClient _lookupClient;
        private readonly KeyVaultClient _keyVaultClient;
        private readonly IAzure _azure;

        private string _applicationGatewayIp;

        public AddCertificateFunctions(IHttpClientFactory httpClientFactory, CertbotConfiguration configuration, LookupClient lookupClient, KeyVaultClient keyVaultClient, IAzure azure)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _lookupClient = lookupClient;
            _keyVaultClient = keyVaultClient;
            _azure = azure;
        }

        [FunctionName("AddCertificateFunctions_HttpStart")]
        public async Task<HttpResponseMessage> HttpStart(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post")]HttpRequestMessage req,
            [DurableClient]IDurableOrchestrationClient starter,
            ILogger log)
        {
            var request = JsonConvert.DeserializeObject<AddCertificateRequest>(await req.Content.ReadAsStringAsync());

            if (request?.Domains == null || request.Domains.Length == 0)
            {
                return req.CreateErrorResponse(HttpStatusCode.BadRequest, $"{nameof(request.Domains)} is empty.");
            }

            // Function input comes from the request content.
            string instanceId = await starter.StartNewAsync("AddCertificateFunctions", request.Domains);

            log.LogInformation($"Started orchestration with ID = '{instanceId}'.");

            return starter.CreateCheckStatusResponse(req, instanceId, true);
        }

        [FunctionName("AddCertificateFunctions")]
        public async Task RunOrchestrator([OrchestrationTrigger] IDurableOrchestrationContext context)
        {
            var domains = context.GetInput<string[]>();

            var applicationGateway = await _azure.ApplicationGateways.GetByResourceGroupAsync(_configuration.ApplicationGatewayResourceGroup, _configuration.ApplicationGatewayName);
            var publicIpResourceId = applicationGateway.PublicFrontends.FirstOrDefault().Value?.Inner.PublicIPAddress.Id;
            if (publicIpResourceId == null) throw new Exception();
            var publicIp = await _azure.PublicIPAddresses.GetByIdAsync(publicIpResourceId);
            _applicationGatewayIp = publicIp.Inner.IpAddress;

            foreach (var domain in domains)
            {
                var isDnsResolving = await context.CallActivityAsync<bool>("AddCertificateFunctions_CheckDnsResolution", domain);

                if (!isDnsResolving) throw new Exception($"Domain name {domain} is not resolving to Application Gateway.");
            }
        }

        /// <summary>
        /// Check whether the domain resolves to the IP of the Application Gateway.
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName("AddCertificateFunctions_CheckDnsResolution")]
        public async Task<bool> CheckDnsResolutionAsync([ActivityTrigger] string domain, ILogger log)
        {
            log.LogInformation($"Checking domain resolution for {domain}");

            var cnameResult = await _lookupClient.QueryAsync(domain, QueryType.CNAME);
            var cnames = cnameResult.Answers.OfType<CNameRecord>().ToList();

            var result = await _lookupClient.QueryAsync(cnames[0].CanonicalName, QueryType.A);
            var ip = result.Answers.OfType<ARecord>().FirstOrDefault()?.Address.ToString();

            return ip == _applicationGatewayIp;
        }
    }
}