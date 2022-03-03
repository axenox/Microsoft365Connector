<?php
namespace axenox\Microsoft365Connector\CommonLogic\Security\Authenticators;

use axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Authenticator;
use TheNetworg\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use exface\Core\DataTypes\EncryptedDataType;

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
 * @author Andrej Kabachnik
 *
 */
class MicrosoftOAuth2Autenticator extends OAuth2Authenticator
{
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
        try {
            $serialized = EncryptedDataType::decrypt(EncryptedDataType::getSecret($this->getWorkbench()), $encrypted);
            $array = json_decode($serialized, true);
            return new AccessToken($array);
        } catch (\Throwable $e) {
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
        
        if (! $lastName && $fullName = $ownerDetails->claim('name')) {
            list($firstName, $lastName) = $this->explodeName($fullName);
        }
        
        $data = [
            'FIRST_NAME' => $firstName,
            'LAST_NAME' => $lastName,
            'EMAIL' => $ownerDetails->claim('email')
        ];
        
        return $data;
    }
}