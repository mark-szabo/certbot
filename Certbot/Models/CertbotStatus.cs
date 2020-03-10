using Newtonsoft.Json;

namespace Certbot.Models
{
    public class CertbotStatus
    {
        [JsonProperty("status")]
        public string Status { get; set; }
        
        [JsonProperty("message")]
        public string Message { get; set; }
        
        [JsonProperty("error")]
        public string Error { get; set; }
    }
}
