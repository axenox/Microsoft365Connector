<?php

namespace axenox\Microsoft365Connector\DataConnectors\Authentication;

use axenox\Microsoft365Connector\CommonLogic\Security\Authenticators\AzureManagedIdentityAccessToken;
use axenox\Microsoft365Connector\CommonLogic\Security\Authenticators\AzureManagedIdentityRequestToken;
use exface\Core\CommonLogic\UxonObject;
use exface\Core\Exceptions\InvalidArgumentException;
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
 *          "class": "\\axenox\\Microsoft365Connector\\DataConnectors\\Authentication\\AzureManagedIdentityAuth"
 *          "authentication_url": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
 *          "scope": "api://{client_id}/.default",
 *          "client_id": "",
 *          "client_secret": "",
 *          "tenant": "",
 *          "subscription_key": "",
 *      }
 *  }
 * 
 * ```
 */
class AzureManagedIdentityAuth extends AbstractHttpAuthenticationProvider
{
    public const GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials';

    private string $authenticationUrlRaw = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token';
    private ?string $authenticationUrl = null;
    private string $scopeRaw = 'api://{client_id}/.default';
    private ?string $scope = null;
    private string $clientId = '';
    private string $clientSecret = '';
    private string $tenant = '';
    private string $subscriptionKey = '';
    private array $excludeUrls = [];
    private ?AzureManagedIdentityAccessToken $tokenCached = null;

    /**
     * @inheritDoc
     */
    public function authenticate(AuthenticationTokenInterface $token): AuthenticationTokenInterface
    {
        // TODO: Implement authenticate() method.
        // Das brauchen wir vermutlich nicht sofort - das ist nur für die Anmeldung durch Nutzer wichtig
        return $token;
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
     * @inheritDoc
     */
    public function getCredentialsUxon(AuthenticationTokenInterface $authenticatedToken): UxonObject
    {
        if (! $authenticatedToken instanceof AzureManagedIdentityAccessToken) {
            // TODO
            // throw new InvalidArgumentException();
        }
        return new UxonObject([
            'authentication' => [
                'class' => '\\' . get_class($this),
                'scope' => $authenticatedToken->getScope(),
                'client_id' => $this->getClientId(),
                'client_secret' => $this->getClientSecret(),
                'subscription' => $this->getSubscriptionKey(),
                'tenant' => $this->getTenant(),
                'access_token' => $authenticatedToken->toArray(),
            ]
        ]);
    }

    /**
     * @inheritDoc
     */
    public function signRequest(RequestInterface $request): RequestInterface
    {
        if (! $this->needsSigning($request)) {
            return $request;
        }

        $accessToken = $this->getAccessToken();
        if ($accessToken === null || $accessToken->isExpired()) {
            // Fetch access token and save it to credential storage
            $requestToken = new AzureManagedIdentityRequestToken(
                $this->getSubscriptionKey(),
                $this->getTenant(),
                $this->getClientId(),
                $this->getClientSecret(),
                $this->getScope()
            );
            $authenticatedToken = $this->getConnection()->authenticate($requestToken, true, null, false);
        }
        
        return $request->withHeader(
            'Authorization',
            $authenticatedToken->getAuthorizationString()
        )->withHeader(
            'Ocp-Apim-Subscription-Key',
            $authenticatedToken->getSubscriptionKey()
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
     * @see AzureManagedIdentityAuth::getExcludeUrls()
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
     * @return string
     */
    public function getAuthenticationUrl(): string
    {
        // Render placeholders.
        if($this->authenticationUrl === null) {
            $placeholders = $this->getParamPlaceholders();
            $this->authenticationUrl = str_replace(
                array_keys($placeholders),
                $placeholders,
                $this->authenticationUrlRaw
            );
        }
        
        return $this->authenticationUrl;
    }

    /**
     * The connector will acquire its authentication tokens from this URL. 
     * 
     * @uxon-property authentication_url
     * @uxon-type string
     * @uxon-template https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
     * 
     * @param string $authenticationUrl
     * @return $this
     */
    public function setAuthenticationUrl(string $authenticationUrl): AzureManagedIdentityAuth
    {
        $this->authenticationUrlRaw = $authenticationUrl;
        $this->authenticationUrl = null;
        return $this;
    }

    /**
     * @return string
     */
    public function getGrantType(): string
    {
        // Hard-coded, as referenced here: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#:~:text=Required-,Must%20be%20set%20to%20client_credentials.,-Second%20case%3A%20Access
        return self::GRANT_TYPE_CLIENT_CREDENTIALS;
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
    public function setClientId(string $clientId): AzureManagedIdentityAuth
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
     * The client secret that you generated for your app in the app registration portal.
     *
     * @uxon-property client_secret
     * @uxon-type string
     *
     * @param string|null $clientSecret
     * @return AzureManagedIdentityAuth
     */
    public function setClientSecret(?string $clientSecret): AzureManagedIdentityAuth
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
            $placeholders = $this->getParamPlaceholders();
            $this->scope = str_replace(
                array_keys($placeholders),
                $placeholders,
                $this->scopeRaw
            );
        }
        
        return $this->scope;
    }

    /**
     * The resource identifier of the resource you want, suffixed with `.default`.
     *
     * Default value is `api://{client_id}/.default`.
     *
     * @uxon-property scope
     * @uxon-type string
     * @uxon-template api://{client_id}/.default
     *
     * @param string $scope
     * @return AzureManagedIdentityAuth
     */
    public function setScope(string $scope): AzureManagedIdentityAuth
    {
        $this->scopeRaw = $scope;
        $this->scope = null;
        
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
     * @return AzureManagedIdentityAuth
     */
    protected function setExcludeUrls(UxonObject $uxon) : AzureManagedIdentityAuth
    {
        $this->excludeUrls = $uxon->toArray();
        return $this;
    }

    /**
     * @return string
     */
    public function getSubscriptionKey(): string
    {
        return $this->subscriptionKey;
    }

    /**
     * ID of the azure subscription that governs the accessed resource.
     *
     * @uxon-property subscription_key
     * @uxon-type string
     *
     * @param string $subscriptionKey
     * @return AzureManagedIdentityAuth
     */
    public function setSubscriptionKey(string $subscriptionKey): AzureManagedIdentityAuth
    {
        $this->subscriptionKey = $subscriptionKey;
        return $this;
    }

    /**
     * Returns a valid Azure Managed Identities access token, either from cache or fresh from
     * Azure, if no cached token is available or if it has expired.
     * 
     * @return AzureManagedIdentityAccessToken|null
     */
    protected function getAccessToken() : ?AzureManagedIdentityAccessToken
    {       
        return $this->tokenCached;
    }
    
    protected function setAccessToken(UxonObject $uxon) : AzureManagedIdentityAuth
    {
        $this->tokenCached = AzureManagedIdentityAccessToken::fromJson($uxon->toJson());
        return $this;
    }

    /**
     * @return AzureManagedIdentityAccessToken|null
     */
    protected function fetchTokenFromServer() : ?AzureManagedIdentityAccessToken
    {
        $body = 
            'grant_type=' . self::GRANT_TYPE_CLIENT_CREDENTIALS .
            '&client_id=' . $this->getClientId() .
            '&client_secret=' . $this->getClientSecret() .
            '&scope=' . $this->getScope();
        
        $authRequest = new Request(
            'POST',
            $this->getAuthenticationUrl(),
            [],
            $body
        );
        
        $response = $this->getConnection()->sendRequest($authRequest);
        $body = (string) $response->getBody();
        $token = AzureManagedIdentityAccessToken::fromJson($body);
        
        return $this->storeToken($token);
    }

    /**
     * @return AzureManagedIdentityAccessToken|null
     */
    protected function fetchTokenFromStorage() : ?AzureManagedIdentityAccessToken
    {
        $json = $this->getWorkbench()->getContext()->getScopeInstallation()->getVariable($this->getScopeVariable());
        return $json !== null ? AzureManagedIdentityAccessToken::fromJson($json) : null;
    }

    /**
     * @param AzureManagedIdentityAccessToken $token
     * @return AzureManagedIdentityAccessToken
     */
    protected function storeToken(AzureManagedIdentityAccessToken $token) : AzureManagedIdentityAccessToken
    {
        $this->getWorkbench()->getContext()->getScopeInstallation()->setVariable(
            $this->getScopeVariable(),
            $token->toJson()
        );

        return $token;
    }
    
    protected function getScopeVariable() : string
    {
        return 'AzureManagedIdentity_' . $this->getConnection()->getId();
    }

    /**
     * Prepares all UXON properties of this class as standard bracket hash placeholders.
     * 
     * NOTE: This function does not cache its results.
     * 
     * @return array
     */
    protected function getParamPlaceholders() : array
    {
        $uxon = $this->exportUxonObject();
        $phs = [];
        
        foreach ($uxon->getPropertiesAll() as $propName => $val) {
            $phs['{' . $propName . '}'] = $val;
        }
        
        return $phs;
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
    public function setTenant(string $tenant): AzureManagedIdentityAuth
    {
        $this->tenant = $tenant;
        return $this;
    }
}