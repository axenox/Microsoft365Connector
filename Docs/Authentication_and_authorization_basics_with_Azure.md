# Authentication and authorization basics with Azure
AppService can access data in one of two ways as illustrated in the following image.

* Delegated access, an app acting on behalf of a signed-in user.
* App-only access, an app acting with its own identity.

![Access scenarios](Images/sso_access_scenarios.png)

## Delegated access (access on behalf of a user)
The AppService needs to get a token to access a foreign server using the existing OAuth token of the currently logged
in users. The AppService will call the other service "on behalf" of the logged on user.

### Connection example:
```
 "authentication": {
     "class": "\\axenox\\Microsoft365Connector\\CommonLogic\\Security\\Authenticators\\MicrosoftOAuth2Autenticator",
     "id": "AZURE_AD",
     "name": "Azure AD",
     "client_id": "...",
     "client_secret": "...",
     "tenant": "...",
     "scopes": [
            "Group.Read.All",
            "User.Read",
            "openid",
            "profile",
            "email"
          ],
 }
```
The `scopes` are the permissions that the user/app needs to access the API.
They need to be set in Azure too. You can read more about scopes in [Single-Sign-On with Microsoft Azure via OAuth 2.0](Single-Sign-On_with_Azure_via_OAuth.md).

## App-only access (Access without a user)
In this access scenario, the application acts on its own with no user signed in.
Application access is used in scenarios such as automation and backup.

Connection example:
```
  "authentication": {
    "class": "\\axenox\\Microsoft365Connector\\DataConnectors\\Authentication\\AzureAppRegistrationAuth",
    "client_id": "...",
    "client_secret": ".",
    "tenant": "...",
    "scope": "api://.../.default"
  },
```
The `scope` is build of the `client_id` of the app registration that we are trying to access and the suffix `/.default`.
"default" means, that the app will get all permissions that are assigned to it in Azure.
This is a special scope for app-only access that fetches all app roles / permissions and is not used for delegated access.

The client app must be granted appropriate application permissions of the resource app it's calling.
Once granted, the client app can access the requested data. For more information about permissions look at the [API permissions](#api-permissions) section below.

## App-only access to Microsoft Graph API
Microsoft Graph API has the `client_id` = `00000003-0000-0000-c000-000000000000`.
So the scope for app-only access to Microsoft Graph would be `api://00000003-0000-0000-c000-000000000000/.default`.
Or the more human-readable version can also be used: `https://graph.microsoft.com/.default` .

## API permissions
To enable client applications to access web APIs, you need to add permissions to the client application (in app registration) to access the web API.
Similarly, in the web API, you need to configure access scopes and roles for the client application.

For more information about configuring app permissions for a web API please see the [official Azure documentation](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-configure-app-access-web-apis).

### Microsoft Graph API permissions
The access permissions for Microsoft Graph API are defined in Azure as "API permissions" in the app registration.
Each permission can be a delegated permission (access on behalf of a user) or an application permission (app-only access).
Be aware that a delegated permission will not work for app-only access!

Here is an example of API permissions for Microsoft Graph API:
![API permissions](Images/azure_microsoft_graph_api_permissions.png)


---
For more information about the authentication and authorization basics see the [Overview of permissions and consent in the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview#consent).