# Microsoft Graph as data source

This app contains a template for a data connection to Microsoft Graph. DO NOT use it directly! Copy it and fill in your data as shown below.

You will need a so-called app registration to access Graph API. The setup is the same as for [single-sign-on via OAuth 2.0](Single-Sign-On_with_Azure_via_OAuth.md). 

**NOTE:** If you are using single-sign-on with Azure, it is probably a good idea to use the option `share_token_with_connections` in your authenticator config as [described here](Synchronizing_roles_via_Graph_API.md) even if you do not plan to synchronize user roles. Otherwise users will need to log in to Azure twice: to access the workbench and to interact with Graph data.

```
 {
     "url": "https://graph.microsoft.com/v1.0/",
     "authentication": {
         "class": "\\axenox\\Microsoft365Connector\\DataConnectors\\Authentication\\MicrosoftOAuth2",
         "client_id": "552b11b2-586d-2188-a248-d87fd2et4asd",
         "client_secret": "fx6AG8res5JK4_8l.G-99Xup_T9F7W_iWm",
         "tenant": "d54fb9c0-cd11-4258-321e-7c457895222",
         "scopes": [
             "openid",
             "profile",
             "email",
             "User.Read",
             "Directory.Read.All"
         ],
         "exclude_urls": [
				 "~.*/\\$metadata~"
        	]
     }
 }
```

Microsoft Graph is actually a huge collection of different APIs. Most of them are based on the OData 4 standard - see the documentation for [OData data connectors](https://github.com/ExFace/UrlDataConnector/blob/master/Docs/OData/index.md) for more details.

Microsoft also provides a very good playground called [Graph explorer](https://developer.microsoft.com/en-us/graph/graph-explorer) to look around, try different APIs and find out, what claims you need.