using System;
using System.Collections.Generic;
using System.Text;

namespace Certbot.Models
{
    public class CertbotConfiguration
    {
        public string AcmeEndpoint { get; set; }
        public string AcmeAccountEmail { get; set; }
        public string TenantId { get; set; }
        public string SubscriptionId { get; set; }
        public string ApplicationGatewayResourceGroup { get; set; }
        public string ApplicationGatewayName { get; set; }
        public string ApplicationGatewayHttpSettingsName { get; set; }
        public string ApplicationGatewayBackendName { get; set; }
        public string BlobContainerUrl { get; set; }
        public string KeyVaultBaseUrl { get; set; }
    }
}
