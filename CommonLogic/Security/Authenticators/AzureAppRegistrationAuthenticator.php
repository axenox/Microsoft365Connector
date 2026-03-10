<?php
namespace axenox\Microsoft365Connector\CommonLogic\Security\Authenticators;

use exface\Core\CommonLogic\Security\AuthenticationToken\JWTAuthToken;
use exface\Core\CommonLogic\Security\Authenticators\AbstractAuthenticator;
use exface\Core\Exceptions\Security\AuthenticationFailedError;
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
 * @author Sergej Riel
 */
class AzureAppRegistrationAuthenticator extends AbstractAuthenticator
{
    private const JWT_ERROR_PREFIX = 'Azure App Registration Authenticator Error: ';
    private const ALLOWED_ALGORITHMS = ['RS256','RS384','RS512','PS256','PS384','PS512']; // TODO: maybe place this in the configuration
    private const OPEN_CONFIG_URL_RAW = 'https://login.microsoftonline.com/{tenantId}/v2.0/.well-known/openid-configuration';
    
    // The valid issuers for Azure Entra ID (Azure AD) tokens can be in different formats depending on the token version (v1 or v2).
    private const VALID_ISSUERS_RAW = [
        "https://login.microsoftonline.com/{tenantId}/v2.0",
        "https://sts.windows.net/{tenantId}/",
    ];

    private $authenticatedToken = null;
    
    /**
     * Authenticates the given JWT token by verifying its signature and claims against the Azure Entra ID tenant's JWKS and expected values.
     * 
     * {@inheritDoc}
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
        $tenantId = $token->getExpectedTenantId();
        $expectedAud = $token->getExpectedAudience();
        $requiredRole = $token->getRequiredRole();
        $username = $token->getUsername();

        // Reading the kid from the header.
        $parts = explode('.', $jwtToken);
        if (count($parts) !== 3) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . 'Invalid JWT format (header.payload.signature)');
        }
        [$headerB64] = $parts;

        try {
            $header = json_decode($this->base64UrlDecode($headerB64), true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . 'Invalid JWT header: ' . $e->getMessage(), $e->getCode(), $e);
        }
        
        $kid = $header['kid'] ?? null;
        if (!$kid) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . "JWT header does not contain 'kid'");
        }
        
        // Gets the JWKS (JSON Web Key Set) for the given tenant ID.
        // This contains the public keys that can be used to verify tokens issued by Entra ID (Azure AD) for this tenant.
        
        // You can not just trust the alg in the header, because the token is not verified at this point.
        // The public keys from the JWKS also contain the alg, but not in all cases (not in v1 tokens).
        // That is why we check the alg against a whitelist of allowed algorithms before we use it to parse the JWKS.
        $headerAlg = $header['alg'] ?? null;
        if (!is_string($headerAlg) || !in_array($headerAlg, self::ALLOWED_ALGORITHMS, true)) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . "Unexpected encryption algorithm (alg): " . (string)$headerAlg);
        }

        // Getting the right public key from the JWKS based on the kid.
        $jwks = $this->fetchJwksForTenant($tenantId);
        $keySet = JWK::parseKeySet($jwks, $headerAlg);

        if (!isset($keySet[$kid])) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . "Token header kid is not matching with the JWKS keys kid.");
        }
        $key = $keySet[$kid];
        
        // The public key is used to check whether the token's signature is correct.
        // If so, the claims (payload) are returned.
        // The JWT decoder also checks the signature, "nbf" (not before) and "exp" (expiration) claims,
        // if present, and throws exceptions if the token is not valid or expired.
        try {
            $decoded = JWT::decode($jwtToken, $key);
        } catch (\Exception $e) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . $e->getMessage(), $e->getCode(), $e);
        }
        
        // decoded body with all claims:
        $claims = json_decode(
            json_encode($decoded, JSON_THROW_ON_ERROR), 
            true, flags: 
            JSON_THROW_ON_ERROR
        );

        // Additional checks on the claims (in addition to the signature verification):
        
        $validIssuers = $this->getValidIssuers($tenantId);
        $iss = $claims['iss'] ?? null;
        if (!is_string($iss) || !in_array($iss, $validIssuers, true)) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . "Unexpected Issuer (iss).");
        }

        $aud = $claims['aud'] ?? null;
        $audOk = is_string($aud) ? ($aud === $expectedAud) : (is_array($aud) && in_array($expectedAud, $aud, true));
        if (!$audOk) {
            throw new RuntimeException(self::JWT_ERROR_PREFIX . "Unexpected Audience (aud).");
        }

        $roles = $claims['roles'] ?? [];
        if (!is_array($roles) || !in_array($requiredRole, $roles, true)) {
            throw new RuntimeException( self::JWT_ERROR_PREFIX . " Missing required role: {$requiredRole}");
        }
        
        // If we reach this point, the token is valid and contains the required role.
        // echo json_encode($claims, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
        $authenticatedToken = new JWTAuthToken(
            $jwtToken,
            $username,
            $token->getFacade(),
            $tenantId,
            $expectedAud,
            $requiredRole,  
            $claims
        );
        
        $this->authenticatedToken = $authenticatedToken;
        return $authenticatedToken;
    }

    /**
     * Decodes a Base64URL encoded string. Returns the decoded string or throws an exception if decoding fails.
     * 
     * @param string $data
     * @return string
     */
    function base64UrlDecode(string $data): string
    {
        $data = strtr($data, '-_', '+/');
        $pad = strlen($data) % 4;
        if ($pad) $data .= str_repeat('=', 4 - $pad);
        $decoded = base64_decode($data, true);
        if ($decoded === false) {
            throw new RuntimeException('Base64URL decode failed');
        }
        return $decoded;
    }

    /**
     * Fetches the JWKS (JSON Web Key Set) for a given Entra ID (Azure AD) tenant ID. 
     * It first retrieves the OpenID Connect configuration to find the JWKS URI, 
     * then fetches the JWKS and returns it as an array. 
     * 
     * Throws exceptions if any step fails (e.g. network issues, invalid responses, missing keys).
     * 
     * @param string $tenantId
     * @return array
     * @throws \JsonException
     */
    function fetchJwksForTenant(string $tenantId): array
    {
        $openidConfigUrl = $this->getOpenConfigUrl($tenantId);
        $cfg = json_decode($this->httpGet($openidConfigUrl), true, flags: JSON_THROW_ON_ERROR);

        $jwksUri = $cfg['jwks_uri'] ?? null;
        if (!$jwksUri) {
            throw new RuntimeException('openid-configuration contains no jwks_uri');
        }

        $jwks = json_decode($this->httpGet($jwksUri), true, flags: JSON_THROW_ON_ERROR);
        if (empty($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new RuntimeException('JWKS does not contain any keys');
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
}