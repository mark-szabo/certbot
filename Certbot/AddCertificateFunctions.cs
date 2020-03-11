using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using ACMESharp.Authorizations;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using Azure.Storage.Blobs;
using Certbot.Models;
using DnsClient;
using DnsClient.Protocol;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
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

        private static ReadOnlySpan<byte> X509Separator => new byte[] { 0x0A, 0x0A };

        public AddCertificateFunctions(IHttpClientFactory httpClientFactory, CertbotConfiguration configuration, LookupClient lookupClient, KeyVaultClient keyVaultClient, IAzure azure, BlobContainerClient blobContainerClient, IAcmeProtocolClientFactory acmeProtocolClientFactory)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _lookupClient = lookupClient;
            _keyVaultClient = keyVaultClient;
            _azure = azure;
            _blobContainerClient = blobContainerClient;
            _acmeProtocolClient = acmeProtocolClientFactory.CreateClientAsync().Result;
        }

        [FunctionName("AddCertificateFunctions_HttpStart")]
        public async Task<HttpResponseMessage> HttpStart(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post")]HttpRequestMessage req,
            [DurableClient]IDurableOrchestrationClient starter,
            ILogger log)
        {
            var request = JsonConvert.DeserializeObject<AddCertificateRequest>(await req.Content.ReadAsStringAsync());

            if (request?.Hostnames == null || request.Hostnames.Length == 0)
            {
                return req.CreateErrorResponse(HttpStatusCode.BadRequest, $"{nameof(request.Hostnames)} is empty.");
            }

            if (request.Hostnames.Length != 1)
            {
                return req.CreateErrorResponse(
                    HttpStatusCode.BadRequest,
                    $"{nameof(request.Hostnames)} should contain only one item. If you would like to create multiple certificates in parallel, call the AddMultipleCertificatesFunctions function.");
            }

            // Function input comes from the request content.
            string instanceId = await starter.StartNewAsync("AddCertificateFunctions", input: request.Hostnames[0]);

            log.LogInformation($"Started orchestration with ID = '{instanceId}'.");

            return starter.CreateCheckStatusResponse(req, instanceId, true);
        }

        [FunctionName("AddCertificateFunctions")]
        public async Task RunOrchestrator([OrchestrationTrigger] IDurableOrchestrationContext context)
        {
            var hostname = context.GetInput<string>();

            context.SetCustomStatus(new CertbotStatus
            {
                Status = "GetApplicationGatewayPublicIpStep",
                Message = "Getting Application Gateway public IP address.",
                Error = null,
            });
            var applicationGatewayIp = await context.CallActivityAsync<string>(nameof(GetApplicationGatewayPublicIpAsync), null);

            context.SetCustomStatus(new CertbotStatus
            {
                Status = "CheckDnsResolutionStep",
                Message = $"Checking whether {hostname} is resolving to the Application Gateway.",
                Error = null,
            });
            var isDnsResolving = await context.CallActivityAsync<bool>(nameof(CheckDnsResolutionAsync), (hostname, applicationGatewayIp));

            if (!isDnsResolving)
            {
                context.SetCustomStatus(new CertbotStatus
                {
                    Status = "Failed",
                    Message = $"Hostname {hostname} is not resolving to the Application Gateway.",
                    Error = "HostnameNotResolvingToApplicationGateway",
                });
                throw new InvalidOperationException($"Hostname {hostname} is not resolving to the Application Gateway.");
            }

            context.SetCustomStatus(new CertbotStatus
            {
                Status = "GetAcmeOrderStep",
                Message = "Starting certificate request process with the Certificate Authority.",
                Error = null,
            });
            var order = await context.CallActivityAsync<OrderDetails>(nameof(GetAcmeOrderAsync), hostname);

            var validationBlobs = new List<string>();
            foreach (var authorization in order.Payload.Authorizations)
            {
                context.SetCustomStatus(new CertbotStatus
                {
                    Status = "GetAcmeHttp01ChallengeStep",
                    Message = "Getting hostname ownership verification challenge from the Certificate Authority.",
                    Error = null,
                });
                var (challenge, validationDetails) = await context.CallActivityAsync<(Challenge, Http01ChallengeValidationDetails)>(nameof(GetAcmeHttp01ChallengeAsync), authorization);
                validationBlobs.Add(validationDetails.HttpResourcePath);

                context.SetCustomStatus(new CertbotStatus
                {
                    Status = "UploadValidationFileToBlobStorageStep",
                    Message = "Uploading hostname ownership verification file to Azure Blob Storage.",
                    Error = null,
                });
                await context.CallActivityAsync(nameof(UploadValidationFileToBlobStorageAsync), validationDetails);

                context.SetCustomStatus(new CertbotStatus
                {
                    Status = "AnswerAcmeHttp01ChallengeStep",
                    Message = "Verifying hostname ownership.",
                    Error = null,
                });
                var response = await context.CallHttpAsync(HttpMethod.Get, new Uri(validationDetails.HttpResourceUrl));

                if (response.StatusCode != HttpStatusCode.OK)
                {
                    context.SetCustomStatus(new CertbotStatus
                    {
                        Status = "Failed",
                        Message = $"ACME challenge http_01 validation file could not be found at {validationDetails.HttpResourceUrl}.",
                        Error = "HostnameOwnershipValidationFileNotFound",
                    });
                    throw new InvalidOperationException($"ACME challenge http_01 validation file could not be found at {validationDetails.HttpResourceUrl}.");
                }
                if (response.Content != validationDetails.HttpResourceValue)
                {
                    context.SetCustomStatus(new CertbotStatus
                    {
                        Status = "Failed",
                        Message = $"ACME challenge http_01 validation file content is not valid at {validationDetails.HttpResourceUrl}.",
                        Error = "HostnameOwnershipValidationFileNotValid",
                    });
                    throw new InvalidOperationException($"ACME challenge http_01 validation file content is not valid at {validationDetails.HttpResourceUrl}.");
                }

                await context.CallActivityAsync(nameof(AnswerAcmeHttp01ChallengeAsync), challenge);
            }

            context.SetCustomStatus(new CertbotStatus
            {
                Status = "CheckAcmeOrderStep",
                Message = "Waiting for hostname ownership verification.",
                Error = null,
            });
            var retryOptions = new RetryOptions(firstRetryInterval: TimeSpan.FromSeconds(5), maxNumberOfAttempts: 12) { Handle = RetryStrategy.RetriableException };
            await context.CallActivityWithRetryAsync(nameof(CheckAcmeOrderAsync), retryOptions, order);

            context.SetCustomStatus(new CertbotStatus
            {
                Status = "CreateCertificateStep",
                Message = "Creating certificate.",
                Error = null,
            });
            var certificateSecretId = await context.CallActivityAsync<string>(nameof(CreateCertificateAsync), (hostname, order));

            context.SetCustomStatus(new CertbotStatus
            {
                Status = "DeleteValidationFileFromBlobStorageStep",
                Message = "Deleting verification files from Azure Blob Storage.",
                Error = null,
            });
            // Parallel execution
            var tasks = new List<Task>();
            foreach (var validationBlob in validationBlobs)
            {
                tasks.Add(context.CallActivityAsync(nameof(DeleteValidationFileFromBlobStorageAsync), validationBlob));
            }
            await Task.WhenAll(tasks);

            context.SetCustomStatus(new CertbotStatus
            {
                Status = "ConfigureApplicationGatewayStep",
                Message = "Configuring Application Gateway to use the new certificate.",
                Error = null,
            });
            await context.CallActivityAsync(nameof(ConfigureApplicationGatewayAsync), (hostname, certificateSecretId));

            context.SetCustomStatus(new CertbotStatus
            {
                Status = "Completed",
                Message = "Certbot function successfully completed.",
                Error = null,
            });
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
            if (publicIpResourceId == null) throw new InvalidOperationException("Application Gatway must have a public IP.");
            var publicIp = await _azure.PublicIPAddresses.GetByIdAsync(publicIpResourceId);

            return publicIp.Inner.IpAddress;
        }

        /// <summary>
        /// Check whether the hostname resolves to the IP of the Application Gateway.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(CheckDnsResolutionAsync))]
        public async Task<bool> CheckDnsResolutionAsync([ActivityTrigger] (string, string) input, ILogger log)
        {
            var (hostname, applicationGatewayIp) = input;

            log.LogInformation($"Checking hostname resolution for {hostname}");

            var cnameResult = await _lookupClient.QueryAsync(hostname, QueryType.CNAME);
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
        /// <param name="hostname"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(GetAcmeOrderAsync))]
        public async Task<OrderDetails> GetAcmeOrderAsync([ActivityTrigger] string hostname, ILogger log)
        {
            log.LogInformation($"Getting ACME order for {hostname}");

            var order = await _acmeProtocolClient.CreateOrderAsync(new[] { hostname });

            return order;
        }

        /// <summary>
        /// We ask the CA what we need to do in order to prove that we control the hostname. The CA will look at the hostname name being requested
        /// and issue one or more sets of challenges. These are different ways that the agent can prove control of the hostname. We'll use the http_01 challenge.
        /// </summary>
        /// <param name="authorization"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(GetAcmeHttp01ChallengeAsync))]
        public async Task<(Challenge, Http01ChallengeValidationDetails)> GetAcmeHttp01ChallengeAsync([ActivityTrigger] string authorization, ILogger log)
        {
            log.LogInformation($"Getting ACME http_01 challenge for {authorization}");

            var authz = await _acmeProtocolClient.GetAuthorizationDetailsAsync(authorization);

            var challenge = authz.Challenges.First(x => x.Type == "http-01");
            var validationDetails = AuthorizationDecoder.ResolveChallengeForHttp01(
                authz,
                challenge,
                _acmeProtocolClient.Signer);

            return (challenge, validationDetails);
        }

        /// <summary>
        /// Upload the http-01 ACME challange validation file to Azure Blob Storage.
        /// </summary>
        /// <param name="validationDetails"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(UploadValidationFileToBlobStorageAsync))]
        public async Task UploadValidationFileToBlobStorageAsync([ActivityTrigger] Http01ChallengeValidationDetails validationDetails, ILogger log)
        {
            log.LogInformation($"Uploading ACME validation file to {validationDetails.HttpResourceUrl}");

            var byteArray = Encoding.ASCII.GetBytes(validationDetails.HttpResourceValue);
            using var stream = new MemoryStream(byteArray);

            await _blobContainerClient.DeleteBlobIfExistsAsync(validationDetails.HttpResourcePath);
            await _blobContainerClient.UploadBlobAsync(validationDetails.HttpResourcePath, stream);
        }

        /// <summary>
        /// Let the CA know that we have uploaded the validation file to the correct place.
        /// </summary>
        /// <param name="challenge"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(AnswerAcmeHttp01ChallengeAsync))]
        public async Task AnswerAcmeHttp01ChallengeAsync([ActivityTrigger] Challenge challenge, ILogger log)
        {
            log.LogInformation($"Answering ACME http_01 challenge for {challenge.Url}");

            await _acmeProtocolClient.AnswerChallengeAsync(challenge.Url);
        }

        /// <summary>
        /// Check the ACME order at the CA, maybe our cert is ready.
        /// </summary>
        /// <param name="order"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(CheckAcmeOrderAsync))]
        public async Task CheckAcmeOrderAsync([ActivityTrigger] OrderDetails order, ILogger log)
        {
            log.LogInformation($"Checking ACME order {order.OrderUrl}");

            var refreshedOrder = await _acmeProtocolClient.GetOrderDetailsAsync(order.OrderUrl, order);

            if (refreshedOrder.Payload.Status == "pending")
            {
                // order is pending, wait
                throw new RetriableActivityException("ACME hostname validation is pending.");
            }

            if (refreshedOrder.Payload.Status == "invalid")
            {
                // order is invalid
                throw new InvalidOperationException("Invalid order status.");
            }
        }

        /// <summary>
        /// Create certificate in KeyVault, sign with the CA.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(CreateCertificateAsync))]
        public async Task<string> CreateCertificateAsync([ActivityTrigger] (string, OrderDetails) input, ILogger log)
        {
            var (hostname, order) = input;
            log.LogInformation($"Creating certificate for {hostname}");

            var certificateName = hostname.Replace("*", "wildcard").Replace(".", "-");

            byte[] csr;

            /*var subject = "CN=" + hostname;
            var subjectAlternativeNames = new SubjectAlternativeNames();
            subjectAlternativeNames.DnsNames.Add(hostname);
            var request = await _certificateClient.StartCreateCertificateAsync(
                certificateName,
                new CertificatePolicy("Unknown", subject, subjectAlternativeNames),
                tags: new Dictionary<string, string>
                {
                    { "Issuer", new Uri(_configuration.AcmeEndpoint).Host }
                });

            csr = request.Properties.Csr;*/

            try
            {
                var request = await _keyVaultClient.CreateCertificateAsync(
                    _configuration.KeyVaultBaseUrl,
                    certificateName,
                    new CertificatePolicy
                    {
                        X509CertificateProperties = new X509CertificateProperties
                        {
                            SubjectAlternativeNames = new SubjectAlternativeNames(dnsNames: new List<string> { hostname })
                        }
                    },
                    tags: new Dictionary<string, string>
                    {
                        { "Issuer", new Uri(_configuration.AcmeEndpoint).Host }
                    });

                csr = request.Csr;
            }
            catch (KeyVaultErrorException ex) when (ex.Response.StatusCode == HttpStatusCode.Conflict)
            {
                var base64Csr = await _keyVaultClient.GetPendingCertificateSigningRequestAsync(_configuration.KeyVaultBaseUrl, certificateName);

                csr = Convert.FromBase64String(base64Csr);
            }

            var finalize = await _acmeProtocolClient.FinalizeOrderAsync(order.Payload.Finalize, csr);

            var httpClient = _httpClientFactory.CreateClient();
            var certificateData = await httpClient.GetByteArrayAsync(finalize.Payload.Certificate);

            // We can switch to the new library when this bug is fixed: https://github.com/Azure/azure-sdk-for-net/issues/9986
            //await _certificateClient.MergeCertificateAsync(new MergeCertificateOptions(certificateName, SliceCert(certificateData)));

            var x509Certificates = new X509Certificate2Collection();

            x509Certificates.ImportFromPem(certificateData);

            var cert = await _keyVaultClient.MergeCertificateAsync(_configuration.KeyVaultBaseUrl, certificateName, x509Certificates);

            return cert.SecretIdentifier.Identifier;
        }

        /// <summary>
        /// Delete the http-01 ACME challange validation file from Azure Blob Storage.
        /// </summary>
        /// <param name="validationBlob"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(DeleteValidationFileFromBlobStorageAsync))]
        public async Task DeleteValidationFileFromBlobStorageAsync([ActivityTrigger] string validationBlob, ILogger log)
        {
            log.LogInformation($"Deleting ACME validation file from {validationBlob}");

            await _blobContainerClient.DeleteBlobAsync(validationBlob);
        }

        /// <summary>
        /// Configure Application Gateway with the new certificate.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(ConfigureApplicationGatewayAsync))]
        public async Task ConfigureApplicationGatewayAsync([ActivityTrigger] (string, string) input, ILogger log)
        {
            var (hostname, certificateSecretId) = input;
            log.LogInformation($"Configuring Application Gateway for {hostname}");

            var listenerName = hostname.Replace("*", "wildcard").Replace(".", "-") + "-listener";
            var ruleName = hostname.Replace("*", "wildcard").Replace(".", "-") + "-rule";
            certificateSecretId = Regex.Match(certificateSecretId, @".*\/").Value;

            var applicationGateway = await _azure.ApplicationGateways.GetByResourceGroupAsync(_configuration.ApplicationGatewayResourceGroup, _configuration.ApplicationGatewayName);

            if (!applicationGateway.Listeners.ContainsKey(listenerName))
            {
                await applicationGateway.Update()
                    .DefineListener(listenerName)
                    .WithPublicFrontend()
                    .WithFrontendPort(443)
                    .WithHostName(hostname)
                    .WithHttps()
                    .WithSslCertificateFromKeyVaultSecretId(certificateSecretId)
                    .Attach()
                    .DefineRequestRoutingRule(ruleName)
                    .FromListener(listenerName)
                    .ToBackendHttpConfiguration(_configuration.ApplicationGatewayHttpSettingsName)
                    .ToBackend(_configuration.ApplicationGatewayBackendName)
                    .Attach()
                    .ApplyAsync();
            }
        }

        private static IEnumerable<byte[]> SliceCert(byte[] rawData)
        {
            var collection = new List<byte[]>();

            var rawDataSpan = rawData.AsSpan();

            var separator = rawDataSpan.IndexOf(X509Separator);

            collection.Add(rawDataSpan.Slice(0, separator).ToArray());
            collection.Add(rawDataSpan.Slice(separator + 2).ToArray());

            return collection;
        }
    }
}