<?php

namespace axenox\Microsoft365Connector\CommonLogic\Security\Authenticators;

use exface\Core\Interfaces\Facades\FacadeInterface;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;

class AzureAppRegistrationRequestToken implements AuthenticationTokenInterface
{
    private string $subscription;
    private string $tenant;
    private string $clientId;
    private string $clientSecret;
    private string $scope;

    /**
     * Create a new Azure Managed Identity token.
     *
     * @param string $subscription
     * @param string $tenant
     * @param string $clientId
     * @param string $clientSecret
     * @param string $scope
     */
    public function __construct(
        string $subscription, 
        string $tenant,
        string $clientId, 
        string $clientSecret, 
        string $scope
    )
    {
        $this->subscription = $subscription;
        $this->tenant = $tenant;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->scope = $scope;
    }

    /**
     * @return string
     */
    public function getTenant() : string
    {
        return $this->tenant;
    }

    /**
     * @return string
     */
    public function getClientId() : string
    {
        return $this->clientId;
    }

    /**
     * @return string
     */
    public function getClientSecret() : string
    {
        return $this->clientSecret;
    }

    /**
     * @return string
     */
    public function getScope() : string
    {
        return $this->scope;
    }

    /**
     * @return string
     */
    public function getSubscription() : string
    {
        return $this->subscription;
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