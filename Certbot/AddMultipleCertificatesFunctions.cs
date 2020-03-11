using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.DurableTask;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Certbot
{
    public static class AddMultipleCertificatesFunctions
    {
        [FunctionName("AddMultipleCertificatesFunctions")]
        public static async Task RunOrchestrator([OrchestrationTrigger] IDurableOrchestrationContext context)
        {
            var hostnames = context.GetInput<string[]>();

            // Run multiple flows in parallel
            var tasks = new List<Task>();
            foreach (var hostname in hostnames)
            {
                tasks.Add(context.CallSubOrchestratorAsync("AddCertificateFunctions", hostname));
            }

            await Task.WhenAll(tasks);
        }

        [FunctionName("AddMultipleCertificatesFunctions_HttpStart")]
        public static async Task<HttpResponseMessage> HttpStart(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequestMessage req,
            [DurableClient] IDurableOrchestrationClient starter,
            ILogger log)
        {
            var request = JsonConvert.DeserializeObject<AddCertificateRequest>(await req.Content.ReadAsStringAsync());

            if (request?.Hostnames == null || request.Hostnames.Length == 0)
            {
                return req.CreateErrorResponse(HttpStatusCode.BadRequest, $"{nameof(request.Hostnames)} is empty.");
            }

            // Function input comes from the request content.
            string instanceId = await starter.StartNewAsync("AddMultipleCertificatesFunctions", request.Hostnames);

            log.LogInformation($"Started orchestration with ID = '{instanceId}'.");

            return starter.CreateCheckStatusResponse(req, instanceId, true);
        }
    }
}