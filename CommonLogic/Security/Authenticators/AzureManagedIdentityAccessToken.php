<?php

namespace axenox\Microsoft365Connector\CommonLogic\Security\Authenticators;

use exface\Core\Interfaces\Facades\FacadeInterface;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;

class AzureManagedIdentityAccessToken implements AuthenticationTokenInterface
{
    public const PROP_TOKEN_TYPE = 'token_type';
    public const PROP_EXPIRES_IN = 'expires_in';
    public const PROP_EXPIRATION_TIME = 'expiration_time';
    public const PROP_ACCESS_TOKEN = 'access_token';
    
    private int $expirationTime;
    private string $tokenType;
    private string $accessToken;

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
    public function __construct(int $expirationTime, string $accessToken, string $tokenType = 'Bearer')
    {
        $this->tokenType = $tokenType;
        $this->expirationTime = $expirationTime;
        $this->accessToken = $accessToken;
    }

    /**
     * @param string $json
     * @return AzureManagedIdentityAccessToken
     */
    public static function fromJson(string $json) : AzureManagedIdentityAccessToken
    {
        $json = json_decode($json, true);
        
        if(!key_exists(self::PROP_EXPIRATION_TIME, $json)) {
            $json[self::PROP_EXPIRATION_TIME] = time() + $json[self::PROP_EXPIRES_IN];
        }
        
        return new self(
            $json[self::PROP_EXPIRATION_TIME],
            $json[self::PROP_ACCESS_TOKEN],
            $json[self::PROP_TOKEN_TYPE]
        );
    }

    /**
     * @return string
     */
    public function getTokenType() : string
    {
        return $this->tokenType;
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
     * @return string
     */
    public function toJson() : string
    {
        return json_encode([
            self::PROP_EXPIRATION_TIME => $this->getExpirationTime(),
            self::PROP_ACCESS_TOKEN => $this->getAccessToken(),
            self::PROP_TOKEN_TYPE => $this->getTokenType()
        ]);
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