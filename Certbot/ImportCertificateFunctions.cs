using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Certificates;
using Certbot.Models;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.DurableTask;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Certbot
{
    public class ImportCertificateFunctions
    {
        private readonly CertbotConfiguration _configuration;
        private readonly KeyVaultClient _keyVaultClient;
        private readonly CertificateClient _certificateClient;

        private static ReadOnlySpan<byte> X509Separator => new byte[] { 0x0A, 0x0A };

        public ImportCertificateFunctions(CertbotConfiguration configuration, KeyVaultClient keyVaultClient, CertificateClient certificateClient)
        {
            _configuration = configuration;
            _keyVaultClient = keyVaultClient;
            _certificateClient = certificateClient;
        }

        [FunctionName("ImportCertificateFunctions_HttpStart")]
        public async Task<HttpResponseMessage> HttpStart(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequestMessage req,
            [DurableClient] IDurableOrchestrationClient starter,
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
            string instanceId = await starter.StartNewAsync("ImportCertificateFunctions", input: request.Hostnames[0]);

            log.LogInformation($"Started orchestration with ID = '{instanceId}'.");

            return starter.CreateCheckStatusResponse(req, instanceId, true);
        }

        [FunctionName("ImportCertificateFunctions")]
        public async Task RunOrchestrator([OrchestrationTrigger] IDurableOrchestrationContext context)
        {
            var record = context.GetInput<AddCertificateRequestRecord>();

            context.SetCustomStatus(new CertbotStatus
            {
                Status = "GetApplicationGatewayPublicIpStep",
                Message = "Getting Application Gateway public IP address.",
                Error = null,
            });
            var applicationGatewayIp = await context.CallActivityAsync<string>(nameof(AddCertificateFunctions.GetApplicationGatewayPublicIpAsync), null);

            context.SetCustomStatus(new CertbotStatus
            {
                Status = "CheckDnsResolutionStep",
                Message = $"Checking whether {record.Hostname} is resolving to the Application Gateway.",
                Error = null,
            });
            var isDnsResolving = await context.CallActivityAsync<bool>(nameof(AddCertificateFunctions.CheckDnsResolutionAsync), (record.Hostname, applicationGatewayIp));

            if (!isDnsResolving)
            {
                context.SetCustomStatus(new CertbotStatus
                {
                    Status = "Failed",
                    Message = $"Hostname {record.Hostname} is not resolving to the Application Gateway.",
                    Error = "HostnameNotResolvingToApplicationGateway",
                });
                throw new InvalidOperationException($"Hostname {record.Hostname} is not resolving to the Application Gateway.");
            }

            context.SetCustomStatus(new CertbotStatus
            {
                Status = "ImportCertificateStep",
                Message = "Importing certificate.",
                Error = null,
            });
            var certificateSecretId = await context.CallActivityAsync<string>(nameof(ImportCertificateAsync), record);

            context.SetCustomStatus(new CertbotStatus
            {
                Status = "ConfigureApplicationGatewayStep",
                Message = "Configuring Application Gateway to use the new certificate.",
                Error = null,
            });
            await context.CallActivityAsync(nameof(AddCertificateFunctions.ConfigureApplicationGatewayAsync), (record.Hostname, certificateSecretId));

            context.SetCustomStatus(new CertbotStatus
            {
                Status = "Completed",
                Message = "Certbot function successfully completed.",
                Error = null,
            });
        }

        /// <summary>
        /// Import certificate into KeyVault.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="log"></param>
        /// <returns></returns>
        [FunctionName(nameof(ImportCertificateAsync))]
        public async Task<string> ImportCertificateAsync([ActivityTrigger] AddCertificateRequestRecord record, ILogger log)
        {
            log.LogInformation($"Creating certificate for {record.Hostname}");

            var certificateName = record.Hostname.Replace("*", "wildcard").Replace(".", "-");
            var privateKey = record.PrivateKey
                .Replace("-----BEGIN PRIVATE KEY-----", "")
                .Replace("-----END PRIVATE KEY-----", "");

            var certificateByteArray = Encoding.ASCII.GetBytes(record.Certificate);
            var x509Certificate = new X509Certificate2(certificateByteArray);

            using RSA rsa = RSA.Create();
            var privateKeyByteArray = Convert.FromBase64String(privateKey);
            if (record.Password == null)
            {
                rsa.ImportPkcs8PrivateKey(new ReadOnlySpan<byte>(privateKeyByteArray), out _);
            }
            else
            {
                rsa.ImportEncryptedPkcs8PrivateKey(record.Password, new ReadOnlySpan<byte>(privateKeyByteArray), out _);
            }
            var x509CertificateWithPrivateKey = x509Certificate.CopyWithPrivateKey(rsa);

            // Import certificate with the new Certificate Client
            var cert = await _certificateClient.ImportCertificateAsync(
                new ImportCertificateOptions(certificateName, x509CertificateWithPrivateKey.Export(X509ContentType.Pfx))
                {
                    Password = record.Password
                });

            // Set tags on the imported certificate with the old client. More info: https://github.com/Azure/azure-sdk-for-net/issues/10580
            await _keyVaultClient.UpdateCertificateAsync(cert.Value.Id.AbsoluteUri, tags: new Dictionary<string, string>
                {
                    { "Hostname", record.Hostname }
                });

            return cert.Value.SecretId.AbsoluteUri;
        }
    }
}