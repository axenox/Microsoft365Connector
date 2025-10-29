<?php

namespace axenox\Microsoft365Connector\DataConnectors\Authentication;

use axenox\Microsoft365Connector\CommonLogic\Security\Authenticators\AzureAppRegistrationAccessToken;
use exface\Core\CommonLogic\UxonObject;
use exface\Core\DataTypes\EncryptedDataType;
use exface\Core\Exceptions\InvalidArgumentException;
use exface\Core\Exceptions\Security\AuthenticationFailedError;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use exface\Core\Interfaces\Widgets\iContainOtherWidgets;
use exface\UrlDataConnector\CommonLogic\AbstractHttpAuthenticationProvider;
use GuzzleHttp\Psr7\Request;
use Psr\Http\Message\RequestInterface;

/**
 * ## Example config of data connection
 * 
 * ```
 *  {
 *      "authentication": {
 *          "class": "\\axenox\\Microsoft365Connector\\DataConnectors\\Authentication\\AzureAppRegistrationAuth"
 *          "client_id": "",
 *          "client_secret": "",
 *          "tenant": "",
 *          "subscription": "",
 *      }
 *  }
 * 
 * ```
 */
class AzureAppRegistrationAuth extends AbstractHttpAuthenticationProvider
{
    public const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials';
    private const AUTH_URL_RAW = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token';
    private const SCOPE_RAW = 'api://{client_id}/.default';
    
    private ?string $authenticationUrl = null;
    private ?string $scope = null;
    private string $clientId = '';
    private string $clientSecret = '';
    private string $tenant = '';
    private string $subscription = '';
    private array $excludeUrls = [];
    private ?AzureAppRegistrationAccessToken $tokenCached = null;

    /**
     * @inheritDoc
     */
    public function authenticate(AuthenticationTokenInterface $token): AuthenticationTokenInterface
    {
        return $token;
    }

    /**
     * @inheritDoc
     */
    public function signRequest(RequestInterface $request): RequestInterface
    {
        if (! $this->needsSigning($request)) {
            return $request;
        }
        
        $authenticatedToken = $this->getAccessToken();
        
        if($authenticatedToken === null) {
            return $request;
        }
        
        return $request->withHeader(
            'Authorization',
            $authenticatedToken->getAuthorizationString()
        )->withHeader(
            'Ocp-Apim-Subscription-Key',
            $authenticatedToken->getSubscription()
        );
    }

    /**
     * Check if a requests needs to be signed, by matching it against exclusion patterns defined
     * in `getExcludeUrls()`.
     * 
     * Returns TRUE if the request needs to be signed.
     * 
     * @param RequestInterface $request
     * @return bool
     * 
     * @see AzureAppRegistrationAuth::getExcludeUrls()
     */
    protected function needsSigning(RequestInterface $request) : bool
    {
        $url = $request->getUri()->__toString();
        
        // To avoid infinite recursion, requests for the authentication URL won't be signed.
        if(stripos($url, $this->getAuthenticationUrl()) !== false) {
            return false;
        }
        
        foreach ($this->getExcludeUrls() as $pattern) {
            if (preg_match($pattern, $url)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns a valid AzureAppRegistrationAccess token. Either from cache, if available, or fresh from Azure.
     *
     * @return AzureAppRegistrationAccessToken|null
     */
    protected function getAccessToken() : ?AzureAppRegistrationAccessToken
    {
        $token = $this->tokenCached ?? $this->fetchAccessTokenFromStorage();
        
        if($token === null || $token->isExpired()) {
            $token = $this->fetchAccessTokenFromServer();
        }
        
        return $this->tokenCached = $token;
    }

    /**
     * @return AzureAppRegistrationAccessToken|null
     */
    protected function fetchAccessTokenFromServer() : ?AzureAppRegistrationAccessToken
    {
        $body =
            'grant_type=' . self::GRANT_TYPE_CLIENT_CREDENTIALS .
            '&client_id=' . $this->getClientId() .
            '&client_secret=' . $this->getClientSecret() .
            '&scope=' . $this->getScope();

        $authRequest = new Request(
            'POST',
            $this->getAuthenticationUrl($this->getTenant()),
            [],
            $body
        );

        $response = $this->getConnection()->sendRequest($authRequest);
        $body = (string) $response->getBody();
        
        $token = AzureAppRegistrationAccessToken::fromJson($body, $this->getSubscription());
        return $this->storeAccessToken($token);
    }

    /**
     * @return AzureAppRegistrationAccessToken|null
     * @throws \SodiumException
     */
    protected function fetchAccessTokenFromStorage() : ?AzureAppRegistrationAccessToken
    {
        $json = $this->getWorkbench()->getContext()->getScopeInstallation()->getVariable(
            $this->getScopeVariableName()
        );
        
        if($json === null) {
            return null;
        }
        
        $json = EncryptedDataType::decrypt(
            $this->getEncryptionSecret(),
            $json
        );

        try {
            $token = AzureAppRegistrationAccessToken::fromJson($json);
        } catch (\Throwable $e) {
            return null;
        }
        
        return $token;
    }

    /**
     * @param AzureAppRegistrationAccessToken $token
     * @return AzureAppRegistrationAccessToken
     * @throws \SodiumException
     */
    protected function storeAccessToken(AzureAppRegistrationAccessToken $token) : AzureAppRegistrationAccessToken
    {
        $json = EncryptedDataType::encrypt(
            $this->getEncryptionSecret(),
            json_encode($token->toArray())
        );
        
        $this->getWorkbench()->getContext()->getScopeInstallation()->setVariable(
            $this->getScopeVariableName(),
            $json
        );
        
        return $token;
    }

    /**
     * @return string
     */
    public function getScopeVariableName() : string
    {
        return 'AzureAppRegistration_AccessToken_' . $this->getConnection()->getId();
    }

    /**
     * @inheritDoc
     */
    public function getCredentialsUxon(AuthenticationTokenInterface $authenticatedToken): UxonObject
    {
        if (!$authenticatedToken instanceof AzureAppRegistrationAccessToken || $authenticatedToken->isExpired()) {
            $authenticatedToken = $this->getAccessToken();

            if($authenticatedToken === null || $authenticatedToken->isExpired()) {
                throw new AuthenticationFailedError($this, 'Cannot generate credentials UXON! Could not authenticate credentials.');
            }
        }

        return new UxonObject([
            'authentication' => [
                'class' => '\\' . get_class($this),
                'scope' => $this->getScope(),
                'client_id' => $this->getClientId(),
                'client_secret' => $this->getClientSecret(),
                'subscription' => $this->getSubscription(),
                'tenant' => $this->getTenant(),
                'access_token' => $authenticatedToken->toArray(),
            ]
        ]);
    }

    /**
     * @param string|null $tenant
     * @return string
     */
    public function getAuthenticationUrl(string $tenant = null): string
    {
        // Render placeholders.
        if($this->authenticationUrl === null) {
            $this->authenticationUrl = str_replace(
                '{tenant}',
                $tenant ?? $this->getTenant(),
                self::AUTH_URL_RAW
            );
        }
        
        return $this->authenticationUrl;
    }

    /**
     * @return string|null
     */
    public function getClientId(): ?string
    {
        return $this->clientId;
    }

    /**
     * The application ID that's assigned to your app. You can find this information in the portal where you registered
     * your app.
     * 
     * @uxon-property client_id
     * @uxon-type string
     * 
     * @param string $clientId
     * @return $this
     */
    public function setClientId(string $clientId): AzureAppRegistrationAuth
    {
        $this->clientId = $clientId;
        return $this;
    }

    /**
     * @return string|null
     */
    public function getClientSecret(): ?string
    {
        return $this->clientSecret;
    }

    /**
     * @return string
     * @throws \SodiumException
     */
    protected function getEncryptionSecret() : string
    {
        if($this->getClientSecret() === '') {
            throw new InvalidArgumentException('Failed to generate encryption secret, "client_secret" cannot be empty.');
        }
        
        $secret = sodium_crypto_generichash($this->getClientSecret());

        return base64_encode($secret);
    }

    /**
     * The client secret that you generated for your app in the app registration portal.
     *
     * @uxon-property client_secret
     * @uxon-type string
     *
     * @param string|null $clientSecret
     * @return AzureAppRegistrationAuth
     */
    public function setClientSecret(?string $clientSecret): AzureAppRegistrationAuth
    {
        $this->clientSecret = $clientSecret;
        return $this;
    }

    /**
     * @return string
     */
    public function getScope(): string
    {
        // Render placeholders.
        if($this->scope === null) {
            $this->scope = str_replace(
                '{client_id}',
                $this->getClientId(),
                self::SCOPE_RAW
            );
        }
        
        return $this->scope;
    }

    /**
     * The resource identifier of the resource you want, suffixed with `.default`.
     * 
     * NOTE: The default value is dynamically calculated. Only overwrite this property, 
     * if you know what you are doing. When overwriting, use the fully qualified scope.
     *
     * @uxon-property scope
     * @uxon-type string
     * @uxon-template api://<INSERT client_id>/.default
     *
     * @param string $scope
     * @return AzureAppRegistrationAuth
     */
    public function setScope(string $scope): AzureAppRegistrationAuth
    {
        $this->scope = $scope;
        return $this;
    }

    /**
     * @return array
     */
    public function getExcludeUrls(): array
    {
        return $this->excludeUrls;
    }

    /**
     * URL patterns (regex) to perform without authentication.
     *
     * **NOTE:** each pattern MUST be enclosed in regex delimiters (`/`, `~`, `@`, `;`, `%` or `\``)!
     *
     * If one of the patterns matches the URI of the request, no authentication header
     * will be added. For example: `~.*\$metadata$~` will exclude all URLs ending with `$metadata`.
     *
     * @uxon-property exclude_urls
     * @uxon-type array
     * @uxon-template [""]
     *
     * @param UxonObject $uxon
     * @return AzureAppRegistrationAuth
     */
    protected function setExcludeUrls(UxonObject $uxon) : AzureAppRegistrationAuth
    {
        $this->excludeUrls = $uxon->toArray();
        return $this;
    }

    /**
     * @return string
     */
    public function getSubscription(): string
    {
        return $this->subscription;
    }

    /**
     * ID of the azure subscription that governs the accessed resource.
     *
     * @uxon-property subscription
     * @uxon-type string
     *
     * @param string $subscriptionKey
     * @return AzureAppRegistrationAuth
     */
    public function setSubscription(string $subscriptionKey): AzureAppRegistrationAuth
    {
        $this->subscription = $subscriptionKey;
        return $this;
    }

    /**
     * @return string
     */
    public function getTenant(): string
    {
        return $this->tenant;
    }

    /**
     * The directory tenant that you want to request permission from.
     * 
     * @uxon-property tenant
     * @uxon-type string
     * 
     * @param string $tenant
     * @return $this
     */
    public function setTenant(string $tenant): AzureAppRegistrationAuth
    {
        $this->tenant = $tenant;
        $this->authenticationUrl = null;
        return $this;
    }

    /**
     * @inheritDoc
     */
    public function createLoginWidget(iContainOtherWidgets $container): iContainOtherWidgets
    {
        // TODO: Implement createLoginWidget() method.
        // Das brauchen wir vermutlich nicht sofort - das ist nur für die Anmeldung durch Nutzer wichtig
        return $container;
    }

    /**
     * @inheritDoc
     */
    public function getDefaultRequestOptions(array $defaultOptions): array
    {
        // No special options for Guzzle required
        return $defaultOptions;
    }

    /**
     * @return string
     */
    public function getGrantType(): string
    {
        // Hard-coded, as referenced here: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#:~:text=Required-,Must%20be%20set%20to%20client_credentials.,-Second%20case%3A%20Access
        return self::GRANT_TYPE_CLIENT_CREDENTIALS;
    }
}