<?php
namespace axenox\Microsoft365Connector\CommonLogic\Security\Authenticators;

use exface\Core\CommonLogic\Security\AuthenticationToken\JWTAuthToken;
use exface\Core\CommonLogic\Security\Authenticators\AbstractAuthenticator;
use exface\Core\Exceptions\Security\AuthenticationFailedError;
use exface\Core\Exceptions\Security\AuthenticatorConfigError;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use JsonException;
use RuntimeException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Client;

/**
 * Authenticator for JWT tokens issued by Azure Entra ID (Azure AD) for app registrations.
 * 
 * useful links:
 * - microsoft jwt token decoder: https://jwt.ms/
 * 
 * ## Examples
 * 
 * In System.config.json
 * 
 * ```
 * "SECURITY.AUTHENTICATORS": [
 *  {
 *      "class": "\\axenox\\Microsoft365Connector\\CommonLogic\\Security\\Authenticators\\AzureAppRegistrationAuthenticator",
 *      "id": "MICROSOFT_O_AUTH",
 *      "tenant": "your-tenant-id",
 *      "audience": "api://your-app-id,
 *      "role": "required-role-name"
 *  }
 * ]
 * ```
 * 
 * @author Sergej Riel
 */
class AzureAppRegistrationAuthenticator extends AbstractAuthenticator
{
    private const JWT_ERROR_PREFIX = 'Azure App Registration Authenticator Error: ';
    private const OPEN_CONFIG_URL_RAW = 'https://login.microsoftonline.com/{tenantId}/v2.0/.well-known/openid-configuration';
    
    // The valid issuers for Azure Entra ID (Azure AD) tokens can be in different formats depending on the token version (v1 or v2).
    private const VALID_ISSUERS_RAW = [
        "https://login.microsoftonline.com/{tenantId}/v2.0",
        "https://sts.windows.net/{tenantId}/",
    ];

    private ?string $tenant = null;
    private ?string $audience = null;
    private ?string $role = null;
    
    private $authenticatedToken = null;

    /**
     * Authenticates the given JWT token by verifying its signature and claims against the Azure Entra ID tenant's JWKS and expected values.
     * 
     * {@inheritDoc}
     * @throws JsonException
     * @see \exface\Core\Interfaces\Security\SecurityManagerInterface::authenticate()
     */
    public function authenticate(AuthenticationTokenInterface $token): AuthenticationTokenInterface
    {
        if (($token instanceof JWTAuthToken) === false){
            throw new AuthenticationFailedError($this, 'Invalid token for this authentication. Please check configuration.', null, null, $token);
        }
        
        if ($token->getUsername() === null) {
            throw new AuthenticationFailedError($this, self::JWT_ERROR_PREFIX . 'The expected username was not found. This may be because it is missing inside the web service configuration.', null, null, $token);
        }
        
        $jwtToken = $token->getJWTToken();
        $username = $token->getUsername();
        $header = $token->getHeader();
        
        $tenantId = $this->getTenant();
        $expectedAud = $this->getAudience();
        $requiredRole = $this->getRole();
        
        // Getting the "kid" (key ID) from the JWT header:
        $keyId = $header['kid'] ?? null;
        if (!$keyId) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . "JWT header does not contain 'kid'");
        }

        // Validating public key via tenant JWKS (JSON Web Key Set)
        $jwks = $this->fetchJwksForTenant($tenantId);
        $jwkKeySet = JWK::parseKeySet($jwks, $token->getHeaderAlgorithm());

        if (!isset($jwkKeySet[$keyId])) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . "Token header kid is not matching with the JWKS keys kid.");
        }
        $validPublicKey = $jwkKeySet[$keyId];
        
        // The public key is used to check whether the token's signature is correct.
        // If so, the payload (claims) are returned.
        // The JWT decoder also checks the signature, "nbf" (not before) and "exp" (expiration) in payload,
        // if present, and throws exceptions if the token is not valid or expired.
        try {
            $decodedAndVerifiedJwtToken = JWT::decode($jwtToken, $validPublicKey);
        } catch (\Exception $e) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . $e->getMessage(), $e->getCode(), $e);
        }
        
        $payload = $this->convertDecodedTokenObjToArray($decodedAndVerifiedJwtToken);

        // Payload Verification:
        // - Issuer verification:
        $validIssuers = $this->getValidIssuers($tenantId);
        $issuer = $payload['iss'] ?? null;
        if (!is_string($issuer) || !in_array($issuer, $validIssuers, true)) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . "Unexpected Issuer (iss).");
        }

        // - Audience verification:
        $aud = $payload['aud'] ?? null;
        $audOk = is_string($aud) ? ($aud === $expectedAud) : (is_array($aud) && in_array($expectedAud, $aud, true));
        if (!$audOk) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . "Unexpected Audience (aud).");
        }

        // - Role verification:
        $roles = $payload['roles'] ?? [];
        if (!is_array($roles) || !in_array($requiredRole, $roles, true)) {
            throw new RuntimeException( self::JWT_ERROR_PREFIX . " Missing required role: {$requiredRole}");
        }
        
        // If we reach this point, the token is valid and contains the required role.
        // echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
        $authenticatedToken = new JWTAuthToken(
            $jwtToken,
            $username,
            $token->getFacade(),
            $payload
        );
        
        $this->authenticatedToken = $authenticatedToken;
        return $authenticatedToken;
    }

    /**
     * Fetches the JWKS (JSON Web Key Set) for a given tenant ID. 
     * It first retrieves the OpenID Connect configuration to find the JWKS URI, 
     * then fetches the JWKS and returns it as an array. 
     * 
     * JWKS contains the public keys that can be used to verify tokens issued by Entra ID (Azure AD) for this tenant.
     * 
     * @param string $tenantId
     * @return array
     * @throws \JsonException
     */
    function fetchJwksForTenant(string $tenantId): array
    {
        $jwksUri = $this->getJwksUri($tenantId);

        $jwks = json_decode(
            $this->httpGet($jwksUri), 
            true, 
            flags: JSON_THROW_ON_ERROR
        );
        
        
        if (empty($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . 'JWKS does not contain any keys');
        }

        return $jwks;
    }
    
    /**
     * Gets the valid issuers for the given tenant ID (v1 and v2).
     * This is used to check the "iss" claim in the JWT token against expected values.
     * 
     * @param string $tenantId
     * @return array
     */
    function getValidIssuers(string $tenantId): array
    {
        $issuers = [];
        foreach (self::VALID_ISSUERS_RAW as $issuerTemplate) {
            $issuers[] = str_replace('{tenantId}', $tenantId, $issuerTemplate);
        }
        return $issuers;
    }
    
    /**
     * Gets the OpenID Connect configuration URL for the given tenant ID.
     * This is used to fetch the JWKS URI.
     * 
     * @param string $tenantId
     * @return string
     */
    function getOpenConfigUrl(string $tenantId): string
    {
        return str_replace('{tenantId}', $tenantId, self::OPEN_CONFIG_URL_RAW);
    }

    /**
     * @param $tokenObj
     * @return array
     * @throws JsonException
     */
    function convertDecodedTokenObjToArray($tokenObj) : array
    {
        return json_decode(
            json_encode($tokenObj, JSON_THROW_ON_ERROR),
            true,
            flags: JSON_THROW_ON_ERROR
        );
    }

    /**
     * Gets the JWKS URI from the OpenID Connect configuration for the given tenant ID.
     * This is used to fetch the JWKS for verifying tokens.
     * 
     * @param string $tenantId
     * @return string|null
     * @throws \JsonException
     */
    function getJwksUri(string $tenantId): ?string
    {
        $openConfigUrl = $this->getOpenConfigUrl($tenantId);
        $openIdConfiguration = json_decode(
            $this->httpGet($openConfigUrl), 
            true,
            flags: JSON_THROW_ON_ERROR
        );

        $jwksUri = $openIdConfiguration['jwks_uri'] ?? null;
        
        if (!$jwksUri) {
            throw new RuntimeException('openid-configuration contains no jwks_uri');
        }
        
        return $jwksUri;
    }

    /**
     * Performs an HTTP GET request to the given URL and returns the response body as a string.
     *
     * @param string $url
     * @return string
     */
    function httpGet(string $url): string
    {
        $client = new Client();

        try {
            $response = $client->request('GET', $url, [
                'headers' => [
                    'Accept' => 'application/json',
                ],
            ]);
        } catch (GuzzleException $e) {
            throw new RuntimeException(
                'HTTP GET request failed: ' . $e->getMessage(),
                null,
                $e
            );
        }

        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException(
                'HTTP GET failed with status code ' . $response->getStatusCode()
            );
        }

        return (string) $response->getBody();
    }

    /**
     *
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\Security\SecurityManagerInterface::isAuthenticated()
     */
    public function isAuthenticated(AuthenticationTokenInterface $token) : bool
    {
        return $this->authenticatedToken === $token;
    }

    /**
     *
     * {@inheritDoc}
     * @see \exface\Core\CommonLogic\Security\Authenticators\AbstractAuthenticator::getNameDefault()
     */
    protected function getNameDefault() : string
    {
        return 'Azure JWT Keys';
    }

    /**
     *
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\Security\AuthenticatorInterface::isSupported()
     */
    public function isSupported(AuthenticationTokenInterface $token) : bool {
        return ($token instanceof JWTAuthToken) && $this->isSupportedFacade($token);
    }
    
    /**
     * @return string
     */
    protected function getTenant(): string
    {
        if ($this->tenant === null) {
            throw new AuthenticatorConfigError($this, 'Tenant ID is not set. Please check your configuration.');
        }
        return $this->tenant;
    }

    /**
     * Sets the tenant ID for this authenticator. This is used to determine which Azure Entra ID tenant's JWKS to use for verifying tokens.
     * 
     * @uxon-property tenant
     * @uxon-type string
     * @uxon-required true
     * 
     * @param string $tenant
     * @return $this
     */
    protected function setTenant(string $tenant): AzureAppRegistrationAuthenticator
    {
        $this->tenant = $tenant;
        return $this;
    }

    /**
     * @return string
     */
    protected function getAudience(): string
    {
        if ($this->audience === null) {
            throw new AuthenticatorConfigError($this, 'Audience is not set. Please check your configuration.');
        }
        return $this->audience;
    }
    
    /**
     * Sets the expected audience for the JWT tokens. 
     * This is used to check the "aud" claim in the token against this value.
     * 
     * @uxon-property audience
     * @uxon-type string
     * @uxon-required true
     * 
     * @param string $audience
     * @return $this
     */
    protected function setAudience(string $audience): AzureAppRegistrationAuthenticator
    {
        $this->audience = $audience;
        return $this;
    }

    /**
     * @return string
     */
    protected function getRole(): string
    {
        if ($this->role === null) {
            throw new AuthenticatorConfigError($this, 'Role is not set. Please check your configuration.');
        }
        return $this->role;
    }
    
    /**
     * Sets the required role for the JWT tokens. This is used to check the "roles" claim in the token for the presence of this role.
     * 
     * @uxon-property role
     * @uxon-type string
     * @uxon-required true
     * 
     * @param string $role
     * @return $this
     */
    protected function setRole(string $role): AzureAppRegistrationAuthenticator
    {
        $this->role = $role;
        return $this;
    }
}