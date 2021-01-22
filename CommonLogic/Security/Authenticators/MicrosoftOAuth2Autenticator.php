<?php
namespace axenox\Microsoft365Connector\CommonLogic\Security\Authenticators;

use axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Authenticator;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;

class MicrosoftOAuth2Autenticator extends OAuth2Authenticator
{
    use MicrosoftOAuth2Trait;
    
    protected function getNameDefault(): string
    {
        return 'Microsoft';
    }
}