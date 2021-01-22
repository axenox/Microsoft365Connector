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
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2AccessToken;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use axenox\OAuth2Connector\Exceptions\OAuthInvalidStateException;
use exface\Core\Exceptions\Security\AuthenticationFailedError;
use exface\Core\Exceptions\RuntimeException;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;

trait MicrosoftOAuth2Trait
{
    use OAuth2Trait;
    
    private $provider = null;
    
    private $accessType = 'offline';
    
    protected function exchangeOAuthToken(AuthenticationTokenInterface $token): OAuth2AccessToken
    {
        if ($token instanceof OAuth2AccessToken) {
            if ($token->getAccessToken()->hasExpired()) {
                throw new AuthenticationFailedError($this->getAuthProvider(), 'OAuth token expired: Please sign in again!');
            } else {
                return $token;
            }
        }
        
        if (! $token instanceof OAuth2RequestToken) {
            throw new RuntimeException('Cannot use "' . get_class($token) . '" as OAuth token!');
        }
        
        $clientFacade = $this->getOAuthClientFacade();
        $request = $token->getRequest();
        $requestParams = $request->getQueryParams();
        $provider = $this->getOAuthProvider();
        
        switch (true) {
            
            // If we are not processing a provider response, either use the stored token
            // or redirect ot the provider to start authentication
            case empty($requestParams['code']):
                
                $authOptions = [];
                $oauthToken = $this->getTokenStored();
                if ($oauthToken) {
                    $expired = $oauthToken->hasExpired();
                    if ($expired) {
                        if (! $this->getRefreshToken()) {
                            $authOptions = ['prompt' => 'consent'];
                        } else {
                            $oauthToken = $provider->getAccessToken('refresh_token', [
                                'refresh_token' => $this->getRefreshToken()
                            ]);
                        }
                    }
                }
                if (! $oauthToken || ! empty($authOptions)) {
                    // If we don't have an authorization code then get one
                    $authUrl = $provider->getAuthorizationUrl($authOptions);
                    $redirectUrl = $request->getHeader('Referer')[0];
                    $clientFacade->startOAuthSession(
                        $this->getAuthProvider(),
                        $redirectUrl,
                        [
                            'state' => $provider->getState()
                        ]);
                    $this->getWorkbench()->stop();
                    header('Location: ' . $authUrl);
                    exit;
                }
                break;
                
                // Got an error, probably user denied access
            case !empty($requestParams['error']):
                $clientFacade->stopOAuthSession();
                throw new AuthenticationFailedError($this, 'OAuth2 error: ' . htmlspecialchars($requestParams['error'], ENT_QUOTES, 'UTF-8'));
                
                // If code is not empty and there is no error, process provider response here
            default:
                $sessionVars = $clientFacade->getOAuthSessionVars();
                
                if (empty($requestParams['state']) || $requestParams['state'] !== $sessionVars['state']) {
                    $clientFacade->stopOAuthSession();
                    throw new OAuthInvalidStateException($this, 'Invalid OAuth2 state!');
                }
                
                // Get an access token (using the authorization code grant)
                try {
                    $oauthToken = $provider->getAccessToken('authorization_code', [
                        'code' => $requestParams['code']
                    ]);
                } catch (\Throwable $e) {
                    $clientFacade->stopOAuthSession();
                    throw new AuthenticationFailedError($this->getConnection(), $e->getMessage(), null, $e);
                }
        }
        
        $clientFacade->stopOAuthSession();
        if ($oauthToken) {
            return new OAuth2AccessToken($this->getUsername($oauthToken, $provider), $oauthToken, $token->getFacade());
        }
        
        throw new AuthenticationFailedError($this->getConnection(), 'Please sign in first!');
    }
    
    protected function getOAuthProvider() : AbstractProvider
    {
        $options = [
            'clientId'      => $this->getClientId(),
            'clientSecret'  => $this->getClientSecret(),
            'redirectUri'   => $this->getRedirectUri(),
            'accessType'    => $this->getAccessType()
        ];
        return new Azure($options);
    }
    
    public function getAccessType() : string
    {
        return $this->accessType;
    }
    
    public function setAccessType(string $value) : AuthenticationProviderInterface
    {
        $this->accessType = $value;
        return $this;
    }
    
    /**
     *
     * @param iContainOtherWidgets $container
     * @return WidgetInterface
     */
    protected function createButtonWidget(iContainOtherWidgets $container) : WidgetInterface
    {
        return WidgetFactory::createFromUxonInParent($container, new UxonObject([
            'widget_type' => 'Html',
            'hide_caption' => false,
            'inline' => true,
            'html' => <<<HTML
            
<a href="{$this->getOAuthClientFacade()->buildUrlForProvider($this)}" referrerpolicy="unsafe-url">
    <span style="float: left">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 23 23">
            <path fill="#f3f3f3" d="M0 0h23v23H0z"/>
            <path fill="#f35325" d="M1 1h10v10H1z"/>
            <path fill="#81bc06" d="M12 1h10v10H12z"/>
            <path fill="#05a6f0" d="M1 12h10v10H1z"/>
            <path fill="#ffba08" d="M12 12h10v10H12z"/>
        </svg>
    </span>
    <span style="line-height: 40px; display: inline-block; margin: 3px 3px 3px -4px; background-color: #f3f3f3; padding: 0 8px 0 8px; color: white; font-weight: bold;">
        Sign in with Microsoft
    </span>
</a>

HTML
        ]));
    }
    
    /**
     * 
     * @see axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::setUrlAuthorize()
     */
    protected function setUrlAuthorize(string $value) : AuthenticationProviderInterface
    {
        throw new RuntimeException('Cannot change the URLs for Microsoft OAuth connectors!');
    }
    
    /**
     *
     * @see axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getUrlAuthorize()
     */
    protected function getUrlAuthorize() : string
    {
        return $this->getOAuthProvider()->getBaseAuthorizationUrl();
    }
    
    /**
     * 
     * @see axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::setUrlAccessToken()
     */
    protected function setUrlAccessToken(string $value) : AuthenticationProviderInterface
    {
        throw new RuntimeException('Cannot change the URLs for Microsoft OAuth connectors!');
    }
    
    /**
     *
     * @see axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getUrlAccessToken()
     */
    protected function getUrlAccessToken() : string
    {
        return $this->getOAuthProvider()->getBaseAccessTokenUrl();
    }
    
    /**
     * @see axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::setUrlResourceOwnerDetails()
     */
    protected function setUrlResourceOwnerDetails(string $value) : AuthenticationProviderInterface
    {
        throw new RuntimeException('Cannot change the URLs for Microsoft OAuth connectors!');
    }
    
    /**
     * @see axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getUrlResourceOwnerDetails()
     */
    protected function getUrlResourceOwnerDetails() : string
    {
        return $this->getOAuthProvider()->getResourceOwnerDetailsUrl();
    }
}