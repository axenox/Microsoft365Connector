<?php
namespace axenox\Microsoft365Connector\CommonLogic\Security\Authenticators;

use axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Authenticator;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;

class MicrosoftOAuth2Autenticator extends OAuth2Authenticator
{
    use MicrosoftOAuth2Trait {
        getScopes as getScopesViaTrait;
    }
    
    protected function getNameDefault(): string
    {
        return 'Microsoft 365 / Azure';
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
}