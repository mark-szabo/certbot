using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using ACMESharp.Authorizations;
using ACMESharp.Protocol;
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
        private readonly AcmeProtocolClient _acmeProtocolClient;

        public AddCertificateFunctions(IHttpClientFactory httpClientFactory, CertbotConfiguration configuration, LookupClient lookupClient, KeyVaultClient keyVaultClient, IAzure azure, AcmeProtocolClient acmeProtocolClient)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _lookupClient = lookupClient;
            _keyVaultClient = keyVaultClient;
            _azure = azure;
            _acmeProtocolClient = acmeProtocolClient;
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

            var applicationGatewayIp = await context.CallActivityAsync<string>("AddCertificateFunctions_GetApplicationGatewayPublicIp", null);

            foreach (var domain in domains)
            {
                var isDnsResolving = await context.CallActivityAsync<bool>("AddCertificateFunctions_CheckDnsResolution", (domain, applicationGatewayIp));

                // TODO: enable this after app migration to Azure
                // if (!isDnsResolving) throw new Exception($"Domain name {domain} is not resolving to Application Gateway.");

                var challanges = context.CallActivityAsync<List<Http01ChallengeValidationDetails>>("AddCertificateFunctions_GetAcmeChallengesAsync", domain);
            }
        }

        /// <summary>
        /// Get the publis IP address of the Application Gateway from the Azure Management API.
        /// </summary>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName("AddCertificateFunctions_GetApplicationGatewayPublicIp")]
        public async Task<string> GetApplicationGatewayPublicIpAsync([ActivityTrigger] object input, ILogger log)
        {
            log.LogInformation("Getting Application Gateway public IP address.");

            var applicationGateway = await _azure.ApplicationGateways.GetByResourceGroupAsync(_configuration.ApplicationGatewayResourceGroup, _configuration.ApplicationGatewayName);
            var publicIpResourceId = applicationGateway.PublicFrontends.FirstOrDefault().Value?.Inner.PublicIPAddress.Id;
            if (publicIpResourceId == null) throw new Exception();
            var publicIp = await _azure.PublicIPAddresses.GetByIdAsync(publicIpResourceId);

            return publicIp.Inner.IpAddress;
        }

        /// <summary>
        /// Check whether the domain resolves to the IP of the Application Gateway.
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName("AddCertificateFunctions_CheckDnsResolution")]
        public async Task<bool> CheckDnsResolutionAsync([ActivityTrigger] (string, string) input, ILogger log)
        {
            var (domain, applicationGatewayIp) = input;

            log.LogInformation($"Checking domain resolution for {domain}");

            var cnameResult = await _lookupClient.QueryAsync(domain, QueryType.CNAME);
            var cnames = cnameResult.Answers.OfType<CNameRecord>().ToList();

            var result = await _lookupClient.QueryAsync(cnames[0].CanonicalName, QueryType.A);
            var ip = result.Answers.OfType<ARecord>().FirstOrDefault()?.Address.ToString();

            return ip == applicationGatewayIp;
        }

        /// <summary>
        /// We ask the CA what we need to do in order to prove that we control the domain. The CA will look at the domain name being requested
        /// and issue one or more sets of challenges. These are different ways that the agent can prove control of the domain. We'll use the http_01 challenge.
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName("AddCertificateFunctions_GetAcmeChallengesAsync")]
        public async Task<List<Http01ChallengeValidationDetails>> GetAcmeChallengesAsync([ActivityTrigger] string domain, ILogger log)
        {
            log.LogInformation($"Getting ACME challenges for {domain}");

            var order = await _acmeProtocolClient.CreateOrderAsync(new[] { domain });

            var challanges = new List<Http01ChallengeValidationDetails>();
            foreach (var authorization in order.Payload.Authorizations)
            {
                var authz = await _acmeProtocolClient.GetAuthorizationDetailsAsync(authorization);

                var challange = AuthorizationDecoder.ResolveChallengeForHttp01(
                    authz,
                    authz.Challenges.First(x => x.Type == "http-01"),
                    _acmeProtocolClient.Signer);

                challanges.Add(challange);
            }

            return challanges;
        }
    }
}