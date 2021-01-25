<?php
namespace axenox\Microsoft365Connector\CommonLogic\Security\Authenticators;

use axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Authenticator;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use TheNetworg\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use exface\Core\DataTypes\EncryptedDataType;

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