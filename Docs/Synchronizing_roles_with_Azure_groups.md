# Synchronizing user roles with Azure groups

In order to outsource the entire user management to Azure, user roles can be "remote controlled" via Azure groups in addition to the [single-sign-on](Single-Sign-On_with_Azure_via_OAuth.md). 

This is common technique used to cerntralize user rights management for different systems. Regardless of the meaning of a user role, an user group is created in Azure Active Directory for every role in each system. User-group-assignments are then retrieved from Azure AD every time the user logs in via singe-sign-on, and transformed to role-assignments in the respective system.

Certralizing user rights management allows IT departments to keep an overview of roles of a specific user in different systems. It also simplifies roll-on and roll-off processes greatly.

Depending on configuration of the specific workbench and Azure AD, there are multiple techniques to synchronize roles possible:

- Single-sing-on via [OAuth2](Single-Sign-On_with_Azure_via_OAuth.md) + [role sync via OAuth token claims](Synchronizing_roles_via_OAuth2_token.md) - recommended since it is the simplest approach.
- Single-sing-on via [OAuth2](Single-Sign-On_with_Azure_via_OAuth.md) + [role sync via Microsoft Graph API](Synchronizing_roles_via_Graph_API.md)
- Single-sing-on via [SAML](Single-Sign-On_with_Azure_via_SAML.md)

## Synchonization principles

If user role sync is configured, an Azure AD group can be mapped to one or more workbench user roles. Every time a user logs in via single-sign-on, the workbench will retrieve this users groups from Azure and give the user the corresponding roles. All other roles the user might have, that are mapped to Azure groups (and thus controlled by Azure) will be removed. 

Should the synchronization mapping be disabled or removed for a certain role, users, that already have it, will keep it.

## Managing groups in Azure 

- Search for "Groups" in the Azure Portal search and proceed to the groups management.
- Add a new group. Choose "Group Type: Security", enter the role name as "Group name" and add owners and members to that group (Screenshot 5).
- When creating the group, you need to set the Option "Azure AD roles can be assigned to the group" to "Yes" (Not seen in Screenshot 5 because for testing purposes a trial version
  of Azure was used). Then you can assign one or more Azure AD roles to the group in the same way as you assign roles to users
  (for more information: https://learn.microsoft.com/en-us/azure/active-directory/roles/groups-concept).

After creating the group you will see your created group in "All groups". The "Object Id" of the group will later be sent via IDToken to the application when a user assigned to that group
tries to login to the application.

## Mapping Azure groups to workbench user roles

See `Administration > Users & Security > User roles`.