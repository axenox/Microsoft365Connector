# Synchronizing user roles with Azure groups via OAuth token claims

Azure AD can be configured to send the list of Azure groups assigned to the user inside the OAuth token.
If you set up external roles in the workbench with the UIDs of ceratin Azure groups, you can "remote control"
user roles by assigning the corresponding groups in Azure.

**NOTE:** this only works for "internal" Azure groups assigned within azure. This does not work for groups
uploaded to azure from external sources like an on-premise AD instance, an IAM tool, or similar. These
external groups will simply be missing in the list. To read them too, [use Microsoft Graph](Synchronizing_roles_via_Graph_API.md).

Here is how to make Azure send groups inside the token

- Navigate to "Token configuration" and click on "add groups claim".
- Select "Security groups" and "Group ID" on "Customize token properties by type"
- Optionally make sure the complete name of the user is included in the token: Create another 
claim via "Add optional claim" and choose "Token type: ID". Select the claim "family_name" to 
make sure that the last name of the user is sent via IDToken to the application.

This will allow Azure to send the group ID via an IDToken when logging in to the application. 
This ID can be matched with the roles created in the application. The users will then be logged in with the 
same roles and permittions that they have be assigned to in Azure.

Notice that the group IDs will only be sent via the IDToken for users created directly within Azure. The 
token will not include group IDs if an external user is trying to sign in to the application.

```
 {
     "class": "\\axenox\\Microsoft365Connector\\CommonLogic\\Security\\Authenticators\\MicrosoftOAuth2Autenticator",
     "id": "AZURE_AD",
     "name": "Azure AD",
     "client_id": "552b11b2-586d-4154-a67b-c57af5a7ccce",
     "client_secret": "fx2NG7jjy0JK8_8l.G-0lXup_T9F7W_iWm",
     "create_new_users": true,
     "sync_roles_with_token_claims": true
 }

```