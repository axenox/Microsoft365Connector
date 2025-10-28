<?php

namespace axenox\Microsoft365Connector\CommonLogic\Security\Authenticators;

use exface\Core\Interfaces\Facades\FacadeInterface;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;

class AzureManagedIdentityRequestToken implements AuthenticationTokenInterface
{
    private $subscriptionKey;
    private $tenant;
    private $clientId;
    private $clientSecret;
    private $scope;

    /**
     * Create a new Azure Managed Identity token.
     * 
     * @param int    $expirationTime
     * Timestamp in seconds, when this token expires.
     * @param string $accessToken
     * The base64 encoded token data.
     * @param string $tokenType
     * The type of this token. Default is `Bearer`.
     */
    public function __construct($subscriptionKey, $tenant, $clientId, $clientSecret, $scope)
    {
        $this->subscriptionKey = $subscriptionKey;
        $this->tenant = $tenant;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->scope = $scope;
    }
    
    public function getTenant() : string
    {
        return $this->tenant;
    }
    
    public function getClientId() : string
    {
        return $this->clientId;
    }
    
    public function getClientSecret() : string
    {
        return $this->clientSecret;
    }
    
    public function getScope() : string
    {
        return $this->scope;
    }

    /**
     * @inheritDoc
     */
    public function getFacade(): ?FacadeInterface
    {
        return null;
    }

    /**
     * @inheritDoc
     */
    public function getUsername(): ?string
    {
        return null;
    }

    /**
     * @inheritDoc
     */
    public function isAnonymous(): bool
    {
        return true;
    }
}