# Microsoft Graph as data source


Microsoft Graph is actually a huge collection of different APIs. Most of them are based on the OData 4 standard - see the documentation for [OData data connectors](https://github.com/ExFace/UrlDataConnector/blob/master/Docs/OData/index.md) for more details.

Microsoft also provides a very good playground called [Graph explorer](https://developer.microsoft.com/en-us/graph/graph-explorer) to look around, try different APIs and find out, what claims you need.

This app contains a template for a data connection to Microsoft Graph: `axenox.Microsoft365Connector.MICROSOFT_GRAPH_TEMPLATE`. DO NOT use it directly! Copy it and fill in your data as shown below.

You will need a so-called app registration to access Graph API. The setup is the same as for [single-sign-on via OAuth 2.0](Single-Sign-On_with_Azure_via_OAuth.md). However, the app registration must have permissions for all desired Graph APIs.

## Access types

- Delegated access (access on behalf of a user)
- App-only access (access without a user)

If you want to learn more about the different access scenarios and scopes, see [Authentication and authorization basics with Azure](Authentication_and_authorization_basics_with_Azure.md).

## Connection configuration

Microsoft Graph API uses OAuth 2.0 for authentication. You can use the same app registration for Graph API as for single-sign-on if you want to.
Just make sure that the app registration has the required permissions to access the Graph API you want to use.

### Delegated access (access on behalf of a user)

```

{
	"url": "https://graph.microsoft.com/v1.0/",
	"authentication": {
		"class": "\\axenox\\Microsoft365Connector\\DataConnectors\\Authentication\\MicrosoftOAuth2",
			"client_id": "552b11b2-586d-2188-a248-d87fd2et4asd",
			"client_secret": "fx6AG8res5JK4_8l.G-99Xup_T9F7W_iWm",
			"tenant": "d54fb9c0-cd11-4258-321e-7c457895222",
			"scopes": [
				""
		],
		"exclude_urls": [
			"~.*/\\$metadata~"
		]
	}
}

```

### Delegated access with single-sign-on and shared tokens

If you are using single-sign-on with Azure, it is probably a good idea to use the option `share_token_with_connections` in your authenticator config as [described here](Synchronizing_roles_via_Graph_API.md) even if you do not plan to synchronize user roles. Otherwise users will need to log in to Azure twice: to access the workbench and to interact with Graph data.

### App-only access (access without a user)

Here is another example of the data connection config for Graph API for App-only access (Access without a user)

```

{
  "url": "https://graph.microsoft.com/v1.0/",
  "authentication": {
    "exclude_urls": [
      "~.*/\\$metadata~"
    ],
    "class": "\\axenox\\Microsoft365Connector\\DataConnectors\\Authentication\\AzureAppRegistrationAuth",
    "client_id": "...",
    "client_secret": "...",
    "tenant": "...",
    "scope": "https://graph.microsoft.com/.default"
  }
}

```

Just swap the "..." with the values from your Azure app registration.