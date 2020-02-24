# Certbot - Certification request and renewal management Azure Function using the ACME protocol

## Configuration parameters

- `AcmeEndpoint` - ACME endpoint (like `https://acme-v02.api.letsencrypt.org/`).
- `AcmeAccountEmail` - Account email to the ACME server.
- `TenantId` - Azure Tenant ID containing all the resources and the managed services identity.
- `SubscriptionId` - Azure Subscription ID containing all the resources.
- `ApplicationGatewayResourceGroup` - Name of the Resource Group containing the Application Gateway.
- `ApplicationGatewayName` - Name of the Application Gateway resource.
- `BlobContainerUrl` - Absolut URL of the container where the `/.well-known/acme-challenge/` path is mapped in the Application Gateway.

## Permissions

- Enable managed service identity for the Azure Function.
- Assign the role `Contributor` and `Storage Blob Data Contributor` to the Storage Account.
- Assign the role `TBD` to the Application Gateway.
