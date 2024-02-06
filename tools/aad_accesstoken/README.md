# Aad retrieve an access token test


# Inside demo/bidding-auction-servers directory
## Azure Active Directory
1. create aad.env file

Example:
```
export ClientApplicationId=<your Azure Active Directory client id>
export ClientSecret=<your Azure Active Directory client secret>
export TenantId=<your Azure Active Directory tenant id>
export AadEndpoint=https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token
export ApiIdentifierUri=<your Azure Active Directory API identifier uri>
```
2. in terminal: 
```
source ./aad.env
tools/aad_accesstoken/test
```
This will export the environment variables to the shell so they can be used in test
## Sample IDP 
1. Goto KMS directory
```
make start-idp
```
2. In new terminal
```
export AadEndpoint=http://localhost:3000/token
tools/aad_accesstoken/test
```
