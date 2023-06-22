<?php
namespace axenox\Microsoft365Connector\CommonLogic\Security\Authenticators;

use axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Authenticator;
use TheNetworg\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use exface\Core\CommonLogic\Security\Authenticators\AbstractAuthenticator;
use exface\Core\DataTypes\EncryptedDataType;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2AuthenticatedToken;
use exface\Core\Exceptions\UnexpectedValueException;

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
 * - Select "Security groups" and "Group ID" on "Customize token properties by type" (Screenshot 6)
 * - Optionally make sure the complete name of the user is included in the token: Create another 
 * claim via "Add optional claim" and choose "Token type: ID". Select the claim "family_name" to 
 * make sure that the last name of the user is sent via IDToken to the application.
 * 
 * This will allow Azure to send the group ID via an IDToken when logging in to the application (Screenshot 7). 
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
 *      "sync_roles": true
 *  }
 * 
 * ```
 * 
 * ### SSO with role sync via Microsoft Graph
 * 
 * **IMPORTANT:** the configuration of the data connection for Microsoft Graph (client_id, secret, tenant, etc.)
 * MUST be identical with that of the authenticator!
 * 
 * ```
 *  {
 *      "class": "\\axenox\\Microsoft365Connector\\CommonLogic\\Security\\Authenticators\\MicrosoftOAuth2Autenticator",
 *      "id": "AZURE_AD",
 *      "name": "Azure AD",
 *      "client_id": "552b11b2-586d-4154-a67b-c57af5a7ccce",
 *      "client_secret": "fx2NG7jjy0JK8_8l.G-0lXup_T9F7W_iWm",
 *      "create_new_users": true,
 *      "sync_roles": true,
 *      "sync_roles_via_ms_graph": true,
 *      "share_token_with_connections": [
 *          "my.App.ConnectionToMicrosoftGraph"
 *      ]
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
class MicrosoftOAuth2Autenticator extends OAuth2Authenticator
{
    
    private $SyncRolesWithDataSheet = null;
    
    use MicrosoftOAuth2Trait {
        getScopes as getScopesViaTrait;
    }
    
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
     * {@inheritDoc}
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Authenticator::getExternalRolesFromToken()
     */
    protected function getExternalRolesFromToken(AuthenticationTokenInterface $token) : array
    {
        if (! $token instanceof OAuth2AuthenticatedToken) {
            throw new UnexpectedValueException('Cannot get external roles from token "' . get_class($token) . '" - expecting AuthenticationTokenInterface');
        }
        
        // returns array of readable group names if "sync_roles_with_data_sheet" is set in auth config
        if(AbstractAuthenticator::hasSyncRolesWithDataSheet() === true) {
            return AbstractAuthenticator::getExternalSyncRoles();
        } 

        // syncRoles method via tokenClaims in Azure AD AccessToken. Returns groupIDs but no readable group names
        $ownerDetails = $this->getOAuthProvider()->getResourceOwner($token->getAccessToken());
        return $ownerDetails->claim('groups') ?? [];
    }
}