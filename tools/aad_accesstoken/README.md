# Aad retrieve an access token test


```bash
# Inside demo/bidding-auction-servers directory
1. create aad.env file

Example:
export ClientApplicationId=<your Azure Active Directory client id>
export ClientSecret=<your Azure Active Directory client secret>
export TenantId=<your Azure Active Directory tenant id>
export AadEndpoint=https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token
export ApiIdentifierUri=<your Azure Active Directory API identifier uri>

2. in terminal: source ./aad.env

This will export the environment variables to the shell so they can be used in test
```
tools/aad_accesstoken/test
```