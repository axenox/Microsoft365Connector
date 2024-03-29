<?php
namespace axenox\Microsoft365Connector\CommonLogic\Security\Authenticators;

use exface\Core\Interfaces\WidgetInterface;
use exface\Core\Interfaces\Widgets\iContainOtherWidgets;
use exface\Core\CommonLogic\UxonObject;
use exface\Core\Interfaces\Security\AuthenticationProviderInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use TheNetworg\OAuth2\Client\Provider\Azure;
use exface\Core\Factories\WidgetFactory;
use axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2AuthenticatedToken;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use exface\Core\Exceptions\Security\AuthenticationFailedError;
use exface\Core\Exceptions\Security\AuthenticationRuntimeError;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use League\OAuth2\Client\Token\AccessTokenInterface;
use axenox\OAuth2Connector\Exceptions\OAuthHttpException;
use exface\Core\Exceptions\Security\AuthenticatorConfigError;

trait MicrosoftOAuth2Trait
{
    use OAuth2Trait;
    
    private $provider = null;
    
    private $tenant = null;
    
    private $autoRefreshToken = true;
    
    /**
     * 
     * @param AuthenticationTokenInterface $token
     * @throws AuthenticationFailedError
     * @throws AuthenticationRuntimeError
     * @throws OAuthHttpException
     * @return OAuth2AuthenticatedToken
     */
    protected function exchangeOAuthToken(AuthenticationTokenInterface $token): OAuth2AuthenticatedToken
    {
        if ($token instanceof OAuth2AuthenticatedToken) {
            if ($token->getAccessToken()->hasExpired()) {
                if ($this->isDebugMode()) {
                    $this->getWorkbench()->getLogger()->debug('OAuth2 authenticator: token of "' . $token->getUsername() . '" expired!');
                }
                throw new AuthenticationFailedError($this->getAuthProvider(), 'OAuth token expired: Please sign in again!');
            } else {
                if ($this->isDebugMode()) {
                    $this->getWorkbench()->getLogger()->debug('OAuth2 authenticator: token of "' . $token->getUsername() . '" still valid - nothing to do!');
                }
                return $token;
            }
        }
        
        if (! $token instanceof OAuth2RequestToken) {
            throw new AuthenticationRuntimeError($this, 'Cannot use "' . get_class($token) . '" as OAuth token!');
        }
        
        $clientFacade = $this->getOAuthClientFacade();
        $request = $token->getRequest();
        $requestParams = $request->getQueryParams();
        $provider = $this->getOAuthProvider();
        
        switch (true) {
            // Got an error, probably user denied access
            case !empty($requestParams['error']):
                $clientFacade->stopOAuthSession();
                $err = $requestParams['error_description'] ?? $requestParams['error'];
                // Wrap the OAuth exception in an ordinary AuthenticationFailedError to ensure they are
                // handled similarly to other types of password-mismatch errors. In particular, they
                // will produce propper 401 HTTP error codes.
                throw new AuthenticationFailedError(
                    $this, 
                    'Failed to sign in with Microsoft account', 
                    null, 
                    new OAuthHttpException($this, 'OAuth2 error: ' . htmlspecialchars($err, ENT_QUOTES, 'UTF-8'), null, null, $request)
                );
            
            // If we are not processing a provider response, either use the stored token
            // or redirect to the provider to start authentication
            case empty($requestParams['code']):
                
                $authOptions = [];
                $oauthToken = $this->getTokenStored();
                if ($oauthToken) {
                    if ($this->isDebugMode()) {
                        $this->getWorkbench()->getLogger()->debug('OAuth2: authentication requested with stored token', $oauthToken->jsonSerialize());
                    }
                    $expired = $oauthToken->hasExpired();
                    if ($expired) {
                        if (! $this->getRefreshToken($oauthToken)) {
                            $authOptions = ['prompt' => 'consent'];
                        } else {
                            $oauthToken = $provider->getAccessToken('refresh_token', [
                                'scope' => $provider->scope,
                                'refresh_token' => $this->getRefreshToken($oauthToken)
                            ]);
                        }
                    }
                } else {
                    if ($this->isDebugMode()) {
                        $this->getWorkbench()->getLogger()->debug('OAuth2: authentication requested without stored token');
                    }
                }
                if (! $oauthToken || ! empty($authOptions)) {
                    // If we don't have an authorization code then get one
                    $authUrl = $provider->getAuthorizationUrl($authOptions);
                    $redirectUrl = $request->getHeader('Referer')[0];
                    $clientFacade->startOAuthSession(
                        $this->getAuthProvider(),
                        $this->getOAuthProviderHash(),
                        $redirectUrl,
                        ['state' => $provider->getState()]
                    );
                    if ($this->isDebugMode()) {
                        $this->getWorkbench()->getLogger()->debug('OAuth2: redirecting to provider', [
                            'oauth_hash' => $this->getOAuthProviderHash(),
                            'oauth_state' => $provider->getState(),
                            'provider_url' => $authUrl
                        ]);
                    }
                    $this->getWorkbench()->stop();
                    header('Location: ' . $authUrl);
                    exit;
                }
                break;
                
            // If code is not empty and there is no error, process provider response here
            default:
                $sessionVars = $clientFacade->getOAuthSessionVars();
                
                if (empty($requestParams['state']) || $requestParams['state'] !== $sessionVars['state']) {
                    $clientFacade->stopOAuthSession();
                    throw new OAuthHttpException($this, 'Invalid OAuth2 state: expecting "' . $sessionVars['state'] . '", received from provider "' . $requestParams['state'] . '"!', null, null, $request);
                }
                
                // Get an access token (using the authorization code grant)
                try {
                    $oauthToken = $provider->getAccessToken('authorization_code', [
                        'scope' => $provider->scope,
                        'code' => $requestParams['code']
                    ]);
                    if ($this->isDebugMode()) {
                        $this->getWorkbench()->getLogger()->debug('OAuth2: response of provider received', [
                            'oauth_session' => $sessionVars,
                            'oauth_access_token' => $oauthToken->jsonSerialize()
                        ]);
                    }
                } catch (\Throwable $e) {
                    $clientFacade->stopOAuthSession();
                    throw new OAuthHttpException($this->getAuthProvider(), 'Cannot get OAuth2 access token from provider response: ' . $e->getMessage(), null, $e, $request);
                }
                
                if ($this->isDebugMode()) {
                    $this->getWorkbench()->getLogger()->debug('OAuth2 authenticator: response of provider processed for user "' . $this->getUsername($oauthToken) . '"', [
                        'username' => $this->getUsername($oauthToken),
                        'oauth_session' => $sessionVars,
                        'oauth_token' => $oauthToken
                    ]);
                }
        }
        
        $clientFacade->stopOAuthSession();
        if ($oauthToken) {
            return new OAuth2AuthenticatedToken($this->getUsername($oauthToken), $oauthToken, $token->getFacade());
        }
        
        throw new AuthenticationFailedError($this->getConnection(), 'Please sign in first!');
    }
    
    /**
     * @see axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getUsername()
     */
    protected function getUsername(AccessTokenInterface $oauthToken) : ?string
    {
        if ($oauthToken->getIdTokenClaims() === null) {
            if ($this->isDebugMode()) {
                $this->getWorkbench()->getLogger()->debug('OAuth2: received token without owner details', $oauthToken->jsonSerialize());
            }
            return '';
        }
        /* @var $ownerDetails \TheNetworg\OAuth2\Client\Provider\AzureResourceOwner */
        $ownerDetails = $this->getOAuthProvider()->getResourceOwner($oauthToken);
        if ($this->isDebugMode()) {
            $this->getWorkbench()->getLogger()->debug('OAuth2: received resource owner details', [
                'resource_owner' => $ownerDetails->toArray(),
                'id_token_claims' => $oauthToken->getIdTokenClaims()
            ]);
        }
        if (($field = $this->getUsernameResourceOwnerField()) !== null) {
            return $ownerDetails->toArray()[$field];
        }
        if (null !== $username = $ownerDetails->claim('preferred_username')) {
            return $username;
        }
        if (null !== $username = $ownerDetails->claim('email')) {
            return $username;
        }
        return $ownerDetails->claim('oid') ?? '';
    }
    
    /**
     * 
     * @return AbstractProvider
     */
    protected function getOAuthProvider() : AbstractProvider
    {
        $options = [
            'clientId'      => $this->getClientId(),
            'clientSecret'  => $this->getClientSecret(),
            'redirectUri'   => $this->getRedirectUri(),
            'defaultEndPointVersion' => Azure::ENDPOINT_VERSION_2_0
        ];
        
        $scopes = $this->getScopes();
        if ($this->getAutoRefreshToken() && ! in_array('offline_access', $scopes)) {
            $scopes[] = 'offline_access';
        }
        if (! empty($scopes)) {
            $options['scopes'] = $scopes;
        }
        
        $provider = new Azure($options);
        if ($this->getTenant() !== null) {
            $provider->tenant = $this->getTenant();
        }
        return $provider;
    }
    
    /**
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::createButtonWidget()
     */
    protected function createButtonWidget(iContainOtherWidgets $container) : WidgetInterface
    {
        return WidgetFactory::createFromUxonInParent($container, new UxonObject([
            'widget_type' => 'Html',
            'hide_caption' => true,
            'inline' => true,
            'html' => <<<HTML
<div style="width: 100%; text-align: center;">            
    <a href="{$this->getOAuthClientFacade()->buildUrlForProvider($this, $this->getOAuthProviderHash())}" referrerpolicy="unsafe-url" style="background-color: rgb(0, 114, 198); display: inline-block; padding-top: 2px; white-space: nowrap">
        <span style="float: left; margin: 3px 3px 3px 5px;">
            <svg width="34" height="34" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 23 23">
                <path fill="#f3f3f3" d="M0 0h23v23H0z"/>
                <path fill="#f35325" d="M1 1h10v10H1z"/>
                <path fill="#81bc06" d="M12 1h10v10H12z"/>
                <path fill="#05a6f0" d="M1 12h10v10H1z"/>
                <path fill="#ffba08" d="M12 12h10v10H12z"/>
            </svg>
        </span>
        <span style="line-height: 34px; display: inline-block; margin: 3px 3px 3px 0; color: white; padding: 0 8px 0 8px; font-weight: bold; white-space: nowrap;">
            {$this->getWorkbench()->getApp('axenox.OAuth2Connector')->getTranslator()->translate('SIGN_IN_WITH')} Microsoft 365
        </span>
    </a>
</div>

HTML
        ]));
    }
    
    /**
     * 
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::setUrlAuthorize()
     */
    protected function setUrlAuthorize(string $value) : AuthenticationProviderInterface
    {
        throw new AuthenticatorConfigError($this, 'Cannot change the URLs for Microsoft OAuth connectors!');
    }
    
    /**
     *
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getUrlAuthorize()
     */
    protected function getUrlAuthorize() : string
    {
        return $this->getOAuthProvider()->getBaseAuthorizationUrl();
    }
    
    /**
     * 
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::setUrlAccessToken()
     */
    protected function setUrlAccessToken(string $value) : AuthenticationProviderInterface
    {
        throw new AuthenticatorConfigError($this, 'Cannot change the URLs for Microsoft OAuth connectors!');
    }
    
    /**
     *
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getUrlAccessToken()
     */
    protected function getUrlAccessToken() : string
    {
        return $this->getOAuthProvider()->getBaseAccessTokenUrl();
    }
    
    /**
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::setUrlResourceOwnerDetails()
     */
    protected function setUrlResourceOwnerDetails(string $value) : AuthenticationProviderInterface
    {
        throw new AuthenticatorConfigError($this, 'Cannot change the URLs for Microsoft OAuth connectors!');
    }
    
    /**
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getUrlResourceOwnerDetails()
     */
    protected function getUrlResourceOwnerDetails() : string
    {
        return $this->getOAuthProvider()->getResourceOwnerDetailsUrl();
    }
    
    /**
     * 
     * @return string|NULL
     */
    protected function getTenant() : ?string
    {
        return $this->tenant;
    }
    
    /**
     * A custom tenant to use (for applications, that are not multi-tenant)
     * 
     * @uxon-property tenant
     * @uxon-type string
     * 
     * @param string $value
     * @return AuthenticationProviderInterface
     */
    protected function setTenant(string $value)
    {
        $this->tenant = $value;
        return $this;
    }
    
    /**
     * 
     * @return bool
     */
    protected function getAutoRefreshToken() : bool
    {
        return $this->autoRefreshToken;
    }
    
    /**
     * Set to FALSE to disable refresh tokens and thus not to request the `offline_access` scope.
     * 
     * @uxon-property auto_refresh_token
     * @uxon-type boolean
     * @uxon-default true
     * 
     * @param bool $value
     * @return MicrosoftOAuth2Trait
     */
    protected function setAutoRefreshToken(bool $value) : MicrosoftOAuth2Trait
    {
        $this->autoRefreshToken = $value;
        return $this;
    }
}