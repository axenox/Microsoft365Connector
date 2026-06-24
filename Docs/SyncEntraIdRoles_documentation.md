## Introduction

The SyncEntraIdRoles action synchronizes the Azure EntraID roles and the mail of given users with the PowerUI.
If the user is not found or has the flag "accountEnabled" set to false in Azure, 
the action can either disable the user in PowerUI or just skip disabling.

This is important if you are using single-sign-on with Azure via OAuth2 and syncing user roles with Azure groups
via MS Graph API as described [in the docs](https://github.com/axenox/Microsoft365Connector/blob/1.x-dev/Docs/Synchronizing_roles_via_Graph_API.md).
In this case, you will have a `MicrosoftOAuth2Autenticator` in your `System.config.json` with a configured
`sync_roles_with_data_sheet`.

Roles are synced every time a user logs on. However, if the user does not, there is no sync. In particular, 
if a user is offboarded, his user roles would remain, although he will probably not be able to log on with SSO. 
This action allows to force-sync roles for any selected user even without a log-in process. Syncing will be done exactly
the same way as when logging in.

To make this work, the action should know which authenticator it should sync: place the id of the `MicrosoftOAuth2Autenticator`
authenticator from `System.config.json` into the actions `authenticator_id` property. When the action is triggered,
it will read user data from the metaobjects `axenox.Microsoft365Connector.users` and `axenox.Microsoft365Connector.userGroups`
and will use the authenticator sync logic with this data.

## Requirements

- `MicrosoftOAuth2Autenticator` authenticator with configured `sync_roles_with_data_sheet` in `System.config.json`.
- "Synchronized external user roles/groups" configured in `Administration > Users&Security > User Roles `
- If you want to sync roles in background: "app-only access" configured in the Azure App Registration for
MS Graph API with permission `Directory.Read.All`.

## Azure Graph API authorization

**NOTE:** reading the above Graph API object requires MS Graph authorization. When the regular on-login sync happens,
this authorization is done via "delegated access" with the same token the user just received through the
single-sign-on process. However, if syncing with this action, the user who presses the button needs to be able to
access MS Graph API.

Read more about [different access scenarios here](https://github.com/axenox/Microsoft365Connector/blob/1.x-dev/Docs/Authentication_and_authorization_basics_with_Azure.md).

### Syncing user roles manually

If it is a human user, who presses the button it should not be a problem as long as this user has logged in using
single-sign-on. Graph API will be called using "delegated access". At the time of logging in, the user was already
authenticated in MS Graph to perform the regular sync. Now this authorization will be reused automatically.

The corresponding Azure app registration needs the permission `User.Read.All` for the regular sync to work and this
should also be enough to sync the roles of a different user with this action.

### Syncing roles in a background process

When syncing with this action from a background process there is no single-sign-on user active, so we must have
a connection configuration for "app-only" access to MS Graph. The data source `axenox.Microsoft365Connector.MICROSOFT_GRAPH`
must then have a connection with `AzureAppRegistrationAuth` authentication configured:

```
 {
     "authentication": {
         "class": "\\axenox\\Microsoft365Connector\\DataConnectors\\Authentication\\AzureAppRegistrationAuth",
         "client_id": "...",
         "client_secret": ".",
         "tenant": "...",
         "scope": "https://graph.microsoft.com/.default"
     }
 }

```

The `client_id`, `client_secret`, etc. are to be found in your app registration. You can use the same app registration
for single-sign-on and this app-only authentication. However, the app-only authentication requires a different
permission: `Directory.Read.All`. The permission `User.Read.All` is not enough here.

If you want to know how to configure the background process with this action in PowerUI, 
please refer to the [background process setup documentation](SyncEntraIdRoles_background_process_setup.md).