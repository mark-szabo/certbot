# Certbot - Certification request and renewal management Azure Function using the ACME protocol

![Architecture](certbot.jpg)

## Architecture

1. The Orchestrator Function is triggered by an HTTP POST request contaning one or more hostnames.
2. The Orchestrator instantly replies with 202 Accepted and a link in the response body, where the status can be queried.
3. Query the public IP address of the Application Gateway, using the Azure REST API.
4. Check if the hostname received is resolving to the IP address of the Application Qateway. (Directly with an A record or through another hostname using a CNAME record.)
5. Start an ACME order with the ACME endpoint (aka. start the process with the CA).
    1. Start the process.
    2. Get the validation file.
6. Upload the validation file to Azure Blob Storage. (A path based rule should direct HTTP traffic there from the Application Gateway. Path: `/.well-known/acme-challenge/*`)
    1. Upload the file.
    2. Answer the ACME challenge (let the CA know thet the file is uploaded).
    3. Wait for the validation (the CA will check the file - this is async, so we regularly poll the CA if it is ready).
    4. Delete the validation file.
7. Create a new Certificate in Azure Key Vault and get the CSR (Certificate Signing Request).
8. Finalize the ACME order (send the CSR to the CA and get back a private key).
9. Merge the certificate created in Key Vault with the private key from the CA and upload this to Key Vault.
10. Configure the Application Gateway.
    1. Create a new HTTPS Listener with the newly created certificate in Key Vault.
    2. Create a Request Routing Rule to route traffic to the predefined (in [configuration](#configuration-parameters)) backend.

## Configuration parameters

- `AcmeEndpoint` - ACME endpoint (like `https://acme-v02.api.letsencrypt.org/`).
- `AcmeAccountEmail` - Account email to the ACME server.
- `TenantId` - Azure Tenant ID containing all the resources and the managed services identity.
- `SubscriptionId` - Azure Subscription ID containing all the resources.
- `ApplicationGatewayResourceGroup` - Name of the Resource Group containing the Application Gateway.
- `ApplicationGatewayName` - Name of the Application Gateway resource.
- `ApplicationGatewayHttpSettingsName` - Name of the HTTP Setting the new Request Routing Rules should use.
- `ApplicationGatewayBackendName` - Name of the Backend Pool where the new Request Routing Rule should route traffic to.
- `BlobContainerUrl` - Absolut URL of the container where the `/.well-known/acme-challenge/*` path is mapped in the Application Gateway.
- `KeyVaultBaseUrl` - Base URL of the Key Vault.

## Permissions

- Enable managed service identity (MSI) for the Azure Function.
- Assign the role `Contributor` **AND** `Storage Blob Data Contributor` to the Storage Account for the MSI.
- Assign the role `Contributor` to the Application Gateway for the MSI.
- Assign the role `Reader` to the Public IP Address of the Application Gateway for the MSI.
- The Application Gateway must have a user assigned managed identity and the following permissions to the Key Vault: `secret/get`, `secret/set`, `certificate/get`, `certificate/create`, `certificate/update`
- Assign the role `Contributor` **AND** `Managed Identity Operator` to the user assigned managed identity for the Function's managed service identity.

## Sample requests

```http
POST /api/AddCertificateFunctions_HttpStart
Content-Type: application/json

{
    "hostnames": [
        { "hostname": "example.com" }
    ]
}
```

```http
POST /api/AddMultipleCertificatesFunctions_HttpStart
Content-Type: application/json

{
    "hostnames": [
        { "hostname": "example1.com" }
        { "hostname": "example2.com" }
    ]
}
```

```http
POST /api/AddCertificateWithPrivateKeyFunctions_HttpStart
Content-Type: application/json

{
    "hostnames": [
        {
            "hostname": "example.com",
            "privatekey": "MIIEvgIBADANBgkqhkiG9<REDACTED>93hzWePHJjijf/peknS",
            "certificate": "MIIFVjCCBD6gAwIBAgIS<REDACTED>+utpV2U/yKdSSC7eDbjNE4="
        }
    ]
}
```

## Sample response

```http
{
    "id": "<instance_id>",
    "statusQueryGetUri": "https://<function_name>.azurewebsites.net/runtime/webhooks/durabletask/instances/<instance_id>?taskHub=<hub_name>&connection=Storage&code=<code>&returnInternalServerErrorOnFailure=true",
    "sendEventPostUri": "https://<function_name>.azurewebsites.net/runtime/webhooks/durabletask/instances/<instance_id>/raiseEvent/{eventName}?taskHub=<hub_name>&connection=Storage&code=<code>",
    "terminatePostUri": "https://<function_name>.azurewebsites.net/runtime/webhooks/durabletask/instances/<instance_id>/terminate?reason={text}&taskHub=<hub_name>&connection=Storage&code=<code>",
    "purgeHistoryDeleteUri": "https://<function_name>.azurewebsites.net/runtime/webhooks/durabletask/instances/<instance_id>?taskHub=<hub_name>&connection=Storage&code=<code>"
}
```

## Status query sample responses

```http
{
    "name": "AddCertificateFunctions",
    "instanceId": "<instance_id>",
    "runtimeStatus": "Running",
    "input": "example.com",
    "customStatus": {
        "status": "CreateCertificateStep",
        "message": "Creating certificate.",
        "error": null
    },
    "output": null,
    "createdTime": "2020-03-24T21:51:49Z",
    "lastUpdatedTime": "2020-03-24T21:52:03Z"
}
```

```http
{
    "name": "AddCertificateFunctions",
    "instanceId": "<instance_id>",
    "runtimeStatus": "Completed",
    "input": "example.com",
    "customStatus": {
        "status": "Completed",
        "message": "Certbot function successfully completed.",
        "error": null
    },
    "output": null,
    "createdTime": "2020-03-24T21:51:49Z",
    "lastUpdatedTime": "2020-03-24T21:52:11Z"
}
```

### Values of `runtimeStatus`

- `Running` - The Function is running. Check the state in `customStatus`.
- `Completed` - The Function has completed.
- `Failed` - An internal error has occuered. Log the response body into the ticket manager (`output` contains more info about the exception).

### Properties of `customStatus`

- `status` - A custom status. [More info.](#values-of-status)
- `message` - A human readable format of the status. You can display this on the frontend.
- `error` - If `status` is `Failed` this field will contain the error code. [More info.](#values-of-error)

### Values of `status`

- `GetApplicationGatewayPublicIpStep` - Getting Application Gateway public IP address.
- `CheckDnsResolutionStep` - Checking whether the hostname is resolving to the Application Gateway.
- `GetAcmeOrderStep` - Starting certificate request process with the Certificate Authority.
- `GetAcmeHttp01ChallengeStep` - Getting hostname ownership verification challenge from the Certificate Authority.
- `UploadValidationFileToBlobStorageStep` - Uploading hostname ownership verification file to Azure Blob Storage.
- `AnswerAcmeHttp01ChallengeStep` - Verifying hostname ownership.
- `CheckAcmeOrderStep` - Waiting for hostname ownership verification.
- `CreateCertificateStep` - Creating certificate.
- `DeleteValidationFileFromBlobStorageStep` - Deleting verification files from Azure Blob Storage.
- `ConfigureApplicationGatewayStep` - Configuring Application Gateway to use the new certificate.
- `Completed` - Certbot function successfully completed.
- `Failed` - An error has occured. Check `error`.
- `ImportCertificateStep` - Importing certificate.

### Values of `error`

- `HostnameNotResolvingToApplicationGateway` - Hostname is not resolving to the Application Gateway.
- `HostnameOwnershipValidationFileNotFound` - ACME challenge http_01 validation file could not be found.
- `HostnameOwnershipValidationFileNotValid` - ACME challenge http_01 validation file content is not valid.
