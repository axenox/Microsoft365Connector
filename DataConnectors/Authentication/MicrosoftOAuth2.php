<?php
namespace axenox\Microsoft365Connector\DataConnectors\Authentication;

use exface\Core\CommonLogic\UxonObject;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2AuthenticatedToken;
use axenox\OAuth2Connector\DataConnectors\Authentication\OAuth2;
use axenox\Microsoft365Connector\CommonLogic\Security\Authenticators\MicrosoftOAuth2Trait;
use TheNetworg\OAuth2\Client\Token\AccessToken;

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