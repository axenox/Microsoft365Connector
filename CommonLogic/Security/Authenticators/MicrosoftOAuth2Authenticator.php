<?php
namespace axenox\Microsoft365Connector\CommonLogic\Security\Authenticators;

use axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Authenticator;
use TheNetworg\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use exface\Core\DataTypes\EncryptedDataType;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2AuthenticatedToken;
use exface\Core\Exceptions\UnexpectedValueException;
use exface\Core\CommonLogic\Security\Authenticators\AbstractAuthenticator;
use exface\Core\Exceptions\Security\AuthenticationRuntimeError;
use exface\Core\Interfaces\UserInterface;

/**
 * Authenticates users using Azure Active Directory via OAuth 2.0.
 * 
 * To enable Single-Sign-On with Microsoft Azure, you need to register the
 * workbench installation (URL) as an "Application" in Azure Active Directory:
 * 
 * 1. Go to https://portal.azure.com/
 * 2. Select Azure Active Directory
 * 3. Proceed to "App registrations" in the menu
 * 4. Create a new registration or select an existing one
 * 
 * You will need to provide a redirect URL: `https://yourdomain.com/path_to_workbench/api/oauth2client`.
 * Make sure you use a secure HTTPS URL with a valid SSL certificate! For testing purposes you can
 * use `http://localhost/path_to_workbench/api/oauth2client`.
 * 
 * You will also need to select required scopes: the default scopes are `openid`, `profile`, `email`
 * unless the `scopes` property of the authenticator is configured explicitly.
 * 
 * After the app registration is complete, you will get the following information required to configure
 * the authenticator in `System.config.json`:
 * 
 * - `Application-ID (Client)` to put into the `client_id` in the authenticator config
 * - `Secret key` (visible under "Certificates and secrets" in the menu inside the registration) to put 
 * into `client_secret`
 * 
 * For more information see the official documentation at https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols.
 * 
 * ## Example Configuration
 * 
 * ### SSO with static roles
 * 
 * ```
 *  {
 *      "class": "\\axenox\\Microsoft365Connector\\CommonLogic\\Security\\Authenticators\\MicrosoftOAuth2Autenticator",
 *      "id": "AZURE_AD",
 *      "name": "Azure AD",
 *      "client_id": "552b11b2-586d-4154-a67b-c57af5a7ccce",
 *      "client_secret": "fx2NG7jjy0JK8_8l.G-0lXup_T9F7W_iWm",
 *      "create_new_users": true,
 *      "create_new_users_with_roles": [
 *          "exface.Core.SUPERUSER"
 *      ]
 *  }
 * 
 * ```
 * 
 * ### SSO with role sync via OAuth2 token
 * 
 * Azure AD can be configured to send the list of Azure groups assigned to the user inside the OAuth token.
 * If you set up external roles in the workbench with the UIDs of ceratin Azure groups, you can "remote control"
 * user roles by assigning the corresponding groups in Azure.
 * 
 * **NOTE:** this only works for "internal" Azure groups assigned within azure. This does not work for groups
 * uploaded to azure from external sources like an on-premise AD instance, an IAM tool, or similar. These
 * external groups will simply be missing in the list. To read them too, use Microsoft Graph as described below.
 * 
 * Here is how to make Azure send groups inside the token
 * 
 * - Navigate to "Token configuration" and click on "add groups claim".
 * - Select "Security groups" and "Group ID" on "Customize token properties by type"
 * - Optionally make sure the complete name of the user is included in the token: Create another 
 * claim via "Add optional claim" and choose "Token type: ID". Select the claim "family_name" to 
 * make sure that the last name of the user is sent via IDToken to the application.
 * 
 * This will allow Azure to send the group ID via an IDToken when logging in to the application. 
 * This ID can be matched with the roles created in the application. The users will then be logged in with the 
 * same roles and permittions that they have be assigned to in Azure.
 * 
 * Notice that the group IDs will only be sent via the IDToken for users created directly within Azure. The 
 * token will not include group IDs if an external user is trying to sign in to the application.
 * 
 * ```
 *  {
 *      "class": "\\axenox\\Microsoft365Connector\\CommonLogic\\Security\\Authenticators\\MicrosoftOAuth2Autenticator",
 *      "id": "AZURE_AD",
 *      "name": "Azure AD",
 *      "client_id": "552b11b2-586d-4154-a67b-c57af5a7ccce",
 *      "client_secret": "fx2NG7jjy0JK8_8l.G-0lXup_T9F7W_iWm",
 *      "create_new_users": true,
 *      "sync_roles_with_token_claims": true
 *  }
 * 
 * ```
 * 
 * ### SSO with role sync via Microsoft Graph
 * 
 * In this case, the Azure groups will be read via Microsoft Graph using the OAuth token provided by Azure during
 * initial authentication. To make this work, you need to tell the authenticator to share the token with the
 * connection to Microsoft Graph via `share_token_with_connections`.
 * 
 * **IMPORTANT:** the configuration of the data connection for Microsoft Graph (client_id, secret, tenant, claims etc.)
 * MUST be identical with that of the authenticator!
 * 
 * ```
 *  {
 *      "class": "\\axenox\\Microsoft365Connector\\CommonLogic\\Security\\Authenticators\\MicrosoftOAuth2Autenticator",
 *      "id": "AZURE_AD",
 *      "name": "Azure AD",
 *      "client_id": "552b11b2-586d-4154-a67b-c57af5a7ccce",
 *      "client_secret": "fx2NG7jjy0JK8_8l.G-0lXup_T9F7W_iWm",
 *      "tenant": "d79fb5c8-cd79-4b9e-857e-7c571213458",
 *      "claims": [
 *          "openid", 
 *          "profile", 
 *          "email",
 *          "User.Read",
 *          "Directory.Read.All"
 *      ],
 *      "create_new_users": true,
 *      "sync_roles_with_data_sheet": {
 *          "object_alias": "axenox.Microsoft365Connector.meGroups",
 *          "columns": [
 *              {
 *                  "attribute_alias": "displayName"
 *              }
 *          ]
 *      },
 *      "share_token_with_connections": [
 *          "my.App.ConnectionToMicrosoftGraph"
 *      ]
 *  }
 * 
 * ```
 * 
 * Here is an example of a corresponding connection configuration. Copy the built-in MS Graph connection
 * and modify its configuration to match that of the authenticator
 * 
 * ```
 *  {
 *      "url": "https://graph.microsoft.com/v1.0/",
 *      "authentication": {
 *          "class": "\\axenox\\Microsoft365Connector\\DataConnectors\\Authentication\\MicrosoftOAuth2",
 *          "client_id": "552b11b2-586d-4154-a67b-c57af5a7ccce",
 *          "client_secret": "fx2NG7jjy0JK8_8l.G-0lXup_T9F7W_iWm",
 *          "tenant": "d79fb5c8-cd79-4b9e-857e-7c571213458",
 *          "scopes": [
 *              "openid",
 *              "profile",
 *              "email",
 *              "User.Read",
 *              "Directory.Read.All"
 *          ]
 *      }
 *  }
 *
 * ```
 * 
 * ## Debugging
 * 
 * Set `debug_log` to `true` in the configuration of the authenticator to get more detailed information
 * in the log. Keep in mind, that this might include sensitive personal information depending on what the
 * provider includes in its responses.
 * 
 * @author Andrej Kabachnik
 *
 */
class MicrosoftOAuth2Authenticator extends OAuth2Authenticator
{
    use MicrosoftOAuth2Trait {
        getScopes as getScopesViaTrait;
    }
    
    private $syncRolesWithTokenClaims = false;
    
    /**
     *
     * {@inheritdoc}
     * @see OAuth2Authenticator::getNameDefault()
     */
    protected function getNameDefault(): string
    {
        return 'via Microsoft 365 / Azure';
    }
    
    /**
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getScopes()
     */
    protected function getScopes() : array
    {
        $scopes = $this->getScopesViaTrait();
        if (empty($scopes)) {
            $scopes = ['openid', 'profile', 'email'];
        }
        return $scopes;
    }
    
    /**
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getTokenStored()
     */
    protected function getTokenStored(): ?AccessTokenInterface
    {
        $encrypted = $this->getWorkbench()->getContext()->getScopeSession()->getVariable('token', $this->getId());
        if ($encrypted) {
            try {
                $serialized = EncryptedDataType::decrypt(EncryptedDataType::getSecret($this->getWorkbench()), $encrypted);
                $array = json_decode($serialized, true);
                return new AccessToken($array, $this->getOAuthProvider());
            } catch (\Throwable $e) {
                $this->getWorkbench()->getLogger()->logException($e);
                return null;
            }
        } else {
            return null;
        }
    }
    
    /**
     *
     * {@inheritdoc}
     * @see OAuth2Authenticator::getNewUserData()
     */
    protected function getNewUserData(AccessTokenInterface $token) : array
    {
        /* @var $ownerDetails \TheNetworg\OAuth2\Client\Provider\AzureResourceOwner */
        $ownerDetails = $this->getOAuthProvider()->getResourceOwner($token);
        
        $firstName = $ownerDetails->getFirstName();
        $lastName = $ownerDetails->getLastName();
        
        if (! $lastName || ! $firstName) {
            $name = $ownerDetails->claim('name');
            list($firstName, $lastName) = $this->explodeName($name);
            if (! $firstName) {
                $firstName = $lastName;
                $lastName = $ownerDetails->claim('family_name');                
            }
        }
        
        $data = [
            'FIRST_NAME' => $firstName,
            'LAST_NAME' => $lastName,
            'EMAIL' => $ownerDetails->claim('email')
        ];
        
        return $data;
    }
    
    /**
     * 
     * @return bool
     */
    protected function hasSyncRolesWithTokenClaims() : bool
    {
        return $this->syncRolesWithTokenClaims;
    }
    
    /**
     * Set to TRUE to sync user roles with OAuth token claims
     * 
     * @uxon-property sync_roles_with_token_claims
     * @uxon-type boolean
     * @uxon-default false
     * 
     * @param bool $value
     * @return MicrosoftOAuth2Authenticator
     */
    protected function setSyncRolesWithTokenClaims(bool $value) : MicrosoftOAuth2Autenticator
    {
        $this->syncRolesWithTokenClaims = $value;
        return $this;
    }
    
    /**
     * In addition to the default role sync options available for all authenticators, this authenticator
     * can sync roles with special "claims" sent along with the token from Azure AD.
     * 
     * {@inheritdoc}
     * @see AbstractAuthenticator::getExternalRolesFromRemote()
     */
    protected function getExternalRolesFromRemote(UserInterface $user, AuthenticationTokenInterface $token) : array
    {
        if ($this->hasSyncRolesWithTokenClaims()) {
            if ($this->hasSyncRolesWithDataSheet()) {
                throw new AuthenticationRuntimeError($this, 'Cannot use `sync_roles_with_data_sheet` and `sync_roles_with_token_claims` at the same time!');
            }
            return $this->getExternalRolesFromToken($token);
        }
        return parent::getExternalRolesFromRemote($user, $token);
    }
    
    /**
     * Reads the group information from an OAuth2 token received from Azure.
     * 
     * If `sync_roles_with_token_claims` is set to `true`, this method will return the GUIDs
     * of all Azure groups the user is member of - not the visible names of the groups.
     * 
     * @param OAuth2AuthenticatedToken $token
     * @return string[]
     */
    protected function getExternalRolesFromToken(AuthenticationTokenInterface $token) : array
    {
        if (! $token instanceof OAuth2AuthenticatedToken) {
            throw new UnexpectedValueException('Cannot get external roles from token "' . get_class($token) . '" - expecting AuthenticationTokenInterface');
        }
        
        $ownerDetails = $this->getOAuthProvider()->getResourceOwner($token->getAccessToken());
        return $ownerDetails->claim('groups') ?? [];
    }
    
    /**
     * 
     * {@inheritdoc}
     * @see AbstractAuthenticator::hasSyncRoles()
     */
    protected function hasSyncRoles() : bool
    {
        return $this->hasSyncRolesWithTokenClaims() || parent::hasSyncRoles();
    }
}