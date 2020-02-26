using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using ACMESharp.Authorizations;
using ACMESharp.Protocol;
using Azure.Storage.Blobs;
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
        private readonly BlobContainerClient _blobContainerClient;
        private readonly AcmeProtocolClient _acmeProtocolClient;

        public AddCertificateFunctions(IHttpClientFactory httpClientFactory, CertbotConfiguration configuration, LookupClient lookupClient, KeyVaultClient keyVaultClient, IAzure azure, BlobContainerClient blobContainerClient, AcmeProtocolClient acmeProtocolClient)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _lookupClient = lookupClient;
            _keyVaultClient = keyVaultClient;
            _azure = azure;
            _blobContainerClient = blobContainerClient;
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

            var applicationGatewayIp = await context.CallActivityAsync<string>(nameof(GetApplicationGatewayPublicIpAsync), null);

            foreach (var domain in domains)
            {
                var isDnsResolving = await context.CallActivityAsync<bool>(nameof(CheckDnsResolutionAsync), (domain, applicationGatewayIp));

                // TODO: enable this after app migration to Azure
                // if (!isDnsResolving) throw new Exception($"Domain name {domain} is not resolving to Application Gateway.");

                var order = await context.CallActivityAsync<OrderDetails>(nameof(GetAcmeOrderAsync), domain);

                foreach (var authorization in order.Payload.Authorizations)
                {
                    var challenge = await context.CallActivityAsync<Http01ChallengeValidationDetails>(nameof(GetAcmeHttp01ChallengeAsync), authorization);

                    await context.CallActivityAsync(nameof(UploadValidationFileToBlobStorageAsync), challenge);

                    var response = await context.CallHttpAsync(HttpMethod.Get, new Uri(challenge.HttpResourceUrl));

                    if (response.StatusCode != HttpStatusCode.OK) throw new Exception($"ACME challenge http_01 validation file could not be found at {challenge.HttpResourceUrl}.");
                    if (response.Content != challenge.HttpResourceValue) throw new Exception($"ACME challenge http_01 validation file content is not valid at {challenge.HttpResourceUrl}.");

                    await context.CallActivityAsync(nameof(AnswerAcmeHttp01ChallengeAsync), challenge);
                }
            }
        }

        /// <summary>
        /// Get the publis IP address of the Application Gateway from the Azure Management API.
        /// </summary>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(GetApplicationGatewayPublicIpAsync))]
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
        [FunctionName(nameof(CheckDnsResolutionAsync))]
        public async Task<bool> CheckDnsResolutionAsync([ActivityTrigger] (string, string) input, ILogger log)
        {
            var (domain, applicationGatewayIp) = input;

            log.LogInformation($"Checking domain resolution for {domain}");

            var cnameResult = await _lookupClient.QueryAsync(domain, QueryType.CNAME);
            var cnames = cnameResult.Answers.OfType<CNameRecord>().ToList();

            if (cnames.Count == 0) return false;

            var result = await _lookupClient.QueryAsync(cnames[0].CanonicalName, QueryType.A);
            var ip = result.Answers.OfType<ARecord>().FirstOrDefault()?.Address.ToString();

            return ip == applicationGatewayIp;
        }

        /// <summary>
        /// An ACME order object represents a client's request for a certificate
        /// and is used to track the progress of that order through to issuance.
        /// Thus, the object contains information about the requested
        /// certificate, the authorizations that the server requires the client
        /// to complete, and any certificates that have resulted from this order.
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(GetAcmeOrderAsync))]
        public async Task<OrderDetails> GetAcmeOrderAsync([ActivityTrigger] string domain, ILogger log)
        {
            log.LogInformation($"Getting ACME order for {domain}");

            var order = await _acmeProtocolClient.CreateOrderAsync(new[] { domain });

            return order;
        }

        /// <summary>
        /// We ask the CA what we need to do in order to prove that we control the domain. The CA will look at the domain name being requested
        /// and issue one or more sets of challenges. These are different ways that the agent can prove control of the domain. We'll use the http_01 challenge.
        /// </summary>
        /// <param name="authorization"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(GetAcmeHttp01ChallengeAsync))]
        public async Task<Http01ChallengeValidationDetails> GetAcmeHttp01ChallengeAsync([ActivityTrigger] string authorization, ILogger log)
        {
            log.LogInformation($"Getting ACME http_01 challenge for {authorization}");

            var authz = await _acmeProtocolClient.GetAuthorizationDetailsAsync(authorization);

            var challange = AuthorizationDecoder.ResolveChallengeForHttp01(
                authz,
                authz.Challenges.First(x => x.Type == "http-01"),
                _acmeProtocolClient.Signer);

            return challange;
        }

        /// <summary>
        /// Upload the http-01 ACME challange validation file to Azure Blob Storage.
        /// </summary>
        /// <param name="challenge"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(UploadValidationFileToBlobStorageAsync))]
        public async Task UploadValidationFileToBlobStorageAsync([ActivityTrigger] Http01ChallengeValidationDetails challenge, ILogger log)
        {
            log.LogInformation($"Uploading ACME validation file to {challenge.HttpResourceUrl}");

            var byteArray = Encoding.ASCII.GetBytes(challenge.HttpResourceValue);
            using var stream = new MemoryStream(byteArray);

            await _blobContainerClient.DeleteBlobIfExistsAsync(challenge.HttpResourcePath);
            await _blobContainerClient.UploadBlobAsync(challenge.HttpResourcePath, stream);
        }

        /// <summary>
        /// Let the CA know that we have uploaded the validation file to the correct place.
        /// </summary>
        /// <param name="challenge"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(GetAcmeHttp01ChallengeAsync))]
        public async Task AnswerAcmeHttp01ChallengeAsync([ActivityTrigger] Http01ChallengeValidationDetails challenge, ILogger log)
        {
            log.LogInformation($"Answering ACME http_01 challenge for {challenge.HttpResourceUrl}");

            await _acmeProtocolClient.AnswerChallengeAsync(challenge.HttpResourceUrl);
        }
    }
}