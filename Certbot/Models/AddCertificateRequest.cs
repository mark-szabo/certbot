using Newtonsoft.Json;

namespace Certbot
{
    public class AddCertificateRequest
    {
        [JsonProperty("hostnames")]
        public AddCertificateRequestRecord[] Hostnames { get; set; }
    }

    public class AddCertificateRequestRecord
    {
        [JsonProperty("hostname")]
        public string Hostname { get; set; }

        [JsonProperty("certificate")]
        public string Certificate { get; set; }

        [JsonProperty("privatekey")]
        public string PrivateKey { get; set; }

        [JsonProperty("password")]
        public string Password { get; set; }
    }
}