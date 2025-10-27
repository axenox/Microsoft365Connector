<?php

namespace axenox\Microsoft365Connector\DataConnectors\Authentication;

use axenox\Microsoft365Connector\CommonLogic\Security\Authenticators\AzureManagedIdentityAccessToken;
use exface\Core\CommonLogic\UxonObject;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use exface\Core\Interfaces\Widgets\iContainOtherWidgets;
use exface\UrlDataConnector\CommonLogic\AbstractHttpAuthenticationProvider;
use Psr\Http\Message\RequestInterface;

/**
 * ## Example config of data connection
 * 
 * ```
 *  {
 *      "authentication": {
 *          "class": "\\axenox\\Microsoft365Connector\\DataConnectors\\Authentication\\AzureManagedIdentityAuth"
 *          "authentication_url": "https://login.microsoftonline.com/4cc..."
 *          "grant_type": "client_credetials",
 *          "client_id": "",
 *          "client_Secret": "",
 *          "scope": ""
 *      }
 *  }
 * 
 * ```
 */
class AzureManagedIdentityAuth extends AbstractHttpAuthenticationProvider
{
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
        // TODO: Implement getCredentialsUxon() method.
        return new UxonObject([
            // TODO probably the entire config of the authenticator (see above)
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
        // TODO: Implement signRequest() method.
        // This is where we need to fetch the access token
        if ($this->getTokenStored() === null || $this->getTokenStored()->isExpired()) {
            $this->refreshAccessToken($this->getTokenStored());
        }
    }
    
    protected function refreshAccessToken(AzureManagedIdentityAccessToken $token = null) : AzureManagedIdentityAccessToken
    {
        // TODO 
        // build request
        // Send it to Azure
        // Instantiate token with response from Azure
        // Compute expiration date. If azure tells us, when it expires, use that. If not, we need a config option for
        // expiration time.
        // $this->getConnection()->sendRequest($authRequest);
    }
    
    protected function needsSigning(RequestInterface $request) : bool
    {
        // TODO add the authentication_url to the exclusion list automatically
        $url = $request->getUri()->__toString();
        foreach ($this->getExcludeUrls() as $pattern) {
            if (preg_match($pattern, $url)) {
                return false;
            }
        }
        return true;
    }
    
    protected function storeToken(AzureManagedIdentityAccessToken $token) : AzureManagedIdentityAccessToken
    {
        $this->getWorkbench()->getContext()->getScopeInstallation()->setVariable('AzureManagedIdentity_' . $this->getConnection()->getId(), 'JSON here');
    }
    
    protected function getTokenStored() : ?AzureManagedIdentityAccessToken
    {
        $this->getWorkbench()->getContext()->getScopeInstallation()->getVariable();
    }
}