<?php
namespace axenox\Microsoft365Connector\DataConnectors\Authentication;

use exface\Core\CommonLogic\UxonObject;
use axenox\OAuth2Connector\DataConnectors\Authentication\OAuth2;
use axenox\Microsoft365Connector\CommonLogic\Security\Authenticators\MicrosoftOAuth2Trait;
use TheNetworg\OAuth2\Client\Token\AccessToken;

/**
 * Authenticates in a data source using the Microsoft OAuth 2.0 protocol (e.g. in Microsoft Graph)
 * 
 * ## Examples
 * 
 * Here is an example configuration for the Microsoft Graph API using an Azure App Registration for authentication.
 * 
 * ```json
 * {
 *  "url": "https://graph.microsoft.com/v1.0/",
 *  "authentication": {
 *      "class": "\\axenox\\Microsoft365Connector\\DataConnectors\\Authentication\\AzureAppRegistrationAuth",
 *      "client_id": "...",
 *      "client_secret": "...",
 *      "tenant": "...",
 *      "scope": "https://graph.microsoft.com/.default"
 *  }
 * }
 * ```
 */
class MicrosoftOAuth2 extends OAuth2
{
    use MicrosoftOAuth2Trait {
        getScopes as getScopesViaTrait;
    }
    
    /**
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getScopes()
     */
    protected function getScopes() : array
    {
        $scopes = $this->getScopesViaTrait();
        if (empty($scopes)) {
            $scopes = ['openid', 'email'];
        }
        return $scopes;
    }
    
    /**
     * 
     * {@inheritdoc}
     * @see OAuth2::setToken()
     */
    protected function setToken($tokenOrUxon) : OAuth2
    {
        if ($tokenOrUxon instanceof UxonObject) {
            return parent::setToken(new AccessToken($tokenOrUxon->toArray(), $this->getOAuthProvider()));
        }
        return parent::setToken($tokenOrUxon);
    }
}