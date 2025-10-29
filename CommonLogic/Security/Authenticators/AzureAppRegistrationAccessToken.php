<?php

namespace axenox\Microsoft365Connector\CommonLogic\Security\Authenticators;

use exface\Core\Interfaces\Facades\FacadeInterface;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;

class AzureAppRegistrationAccessToken implements AuthenticationTokenInterface
{
    public const PROP_SUBSCRIPTION = 'subscription';
    public const PROP_EXPIRES_IN = 'expires_in';
    public const PROP_EXPIRATION_TIME = 'expiration_time';
    public const PROP_ACCESS_TOKEN = 'access_token';
    
    private int $expirationTime;
    private string $accessToken;
    private string $subscription;

    /**
     * Create a new Azure Managed Identity token.
     *
     * @param int    $expirationTime
     * Timestamp in seconds, when this token expires.
     * @param string $accessToken
     * The base64 encoded token data.
     * @param string $subscriptionKey
     * The subscription key governing the resource you are trying to access.
     */
    public function __construct(int $expirationTime, string $accessToken, string $subscriptionKey)
    {
        $this->expirationTime = $expirationTime;
        $this->accessToken = $accessToken;
        $this->subscription = $subscriptionKey;
    }

    /**
     * @param string      $json
     * @param string|null $subscriptionKey
     * Fallback, in case the JSON does not contain a property named `subscription`.
     * @return AzureAppRegistrationAccessToken
     */
    public static function fromJson(string $json, string $subscriptionKey = null) : AzureAppRegistrationAccessToken
    {
        $json = json_decode($json, true);
        
        if(!key_exists(self::PROP_EXPIRATION_TIME, $json)) {
            $json[self::PROP_EXPIRATION_TIME] = time() + $json[self::PROP_EXPIRES_IN];
        }
        
        if(!key_exists(self::PROP_SUBSCRIPTION, $json)) {
            $json[self::PROP_SUBSCRIPTION] = $subscriptionKey;
        }
        
        return new self(
            $json[self::PROP_EXPIRATION_TIME],
            $json[self::PROP_ACCESS_TOKEN],
            $json[self::PROP_SUBSCRIPTION]
        );
    }

    /**
     * @return string
     */
    public function getTokenType() : string
    {
        return 'Bearer';
    }

    /**
     * Returns the base64 encoded token data.
     * 
     * @return string
     */
    public function getAccessToken() : string
    {
        return $this->accessToken;
    }

    /**
     * Returns the full authorization string for the header `Authorization`.
     * 
     * @return string
     */
    public function getAuthorizationString() : string
    {
        return  $this->getTokenType() . ' ' . $this->getAccessToken();
    }

    /**
     * The timestamp in seconds, when this token expires.
     * 
     * @return int
     */
    public function getExpirationTime() : int
    {
        return $this->expirationTime;
    }
    
    public function getSubscription() : string
    {
        return $this->subscription;
    }

    /**
     * Returns TRUE if this token has expired (i.e. is no longer valid).
     * 
     * @return bool
     */
    public function isExpired() : bool
    {
        return time() >= $this->getExpirationTime();
    }

    /**
     * @return array
     */
    public function toArray() : array
    {
        return [
            self::PROP_EXPIRATION_TIME => $this->getExpirationTime(),
            self::PROP_ACCESS_TOKEN => $this->getAccessToken(),
            self::PROP_SUBSCRIPTION => $this->getSubscription()
        ];
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
        return false;
    }
}