<?php
namespace axenox\Microsoft365Connector\DataConnectors\Authentication;

use exface\Core\CommonLogic\UxonObject;
use exface\UrlDataConnector\Interfaces\UrlConnectionInterface;
use exface\Core\CommonLogic\Traits\ImportUxonObjectTrait;
use exface\Core\Interfaces\Security\AuthenticationTokenInterface;
use exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2AuthenticatedToken;
use exface\Core\Exceptions\InvalidArgumentException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use axenox\OAuth2Connector\CommonLogic\Security\AuthenticationToken\OAuth2RequestToken;
use Psr\Http\Message\RequestInterface;
use axenox\Microsoft365Connector\CommonLogic\Security\Authenticators\MicrosoftOAuth2Trait;
use exface\Core\Interfaces\Security\AuthenticationProviderInterface;
use exface\UrlDataConnector\Interfaces\HttpConnectionInterface;

class MicrosoftOAuth2 implements HttpAuthenticationProviderInterface
{
    use ImportUxonObjectTrait;
    use MicrosoftOAuth2Trait {
        getScopes as getScopesViaTrait;
    }
    
    private $connection = null;
    
    private $originalUxon = null;
    
    private $storedToken = null;
    
    private $refreshToken = null;
    
    /**
     *
     * @param UrlConnectionInterface $dataConnection
     * @param UxonObject $uxon
     */
    public function __construct(UrlConnectionInterface $dataConnection, UxonObject $uxon = null)
    {
        $this->connection = $dataConnection;
        if ($uxon !== null) {
            $this->originalUxon = $uxon;
            $this->importUxonObject($uxon, ['class']);
        }
    }
    
    public function authenticate(AuthenticationTokenInterface $token): AuthenticationTokenInterface
    {
        if (! $token instanceof OAuth2RequestToken) {
            throw new InvalidArgumentException('Cannot use token ' . get_class($token) . ' in OAuth2 authentication: only OAuth2RequestToken or derivatives allowed!');
        }
        
        return $this->exchangeOAuthToken($token);
    }
    
    /**
     * @see \axenox\OAuth2Connector\CommonLogic\Security\Authenticators\OAuth2Trait::getScopes()
     */
    protected function getScopes() : array
    {
        $scopes = $this->getScopesViaTrait();
        if (empty($scopes)) {
            $scopes = ['openid', 'email'];
        }
        return $scopes;
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface::getDefaultRequestOptions()
     */
    public function getDefaultRequestOptions(array $defaultOptions): array
    {
        return $defaultOptions;
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface::signRequest()
     */
    public function signRequest(RequestInterface $request) : RequestInterface
    {
        $token = $this->getTokenStored();
        if ($token) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $token->getToken());
        }
        return $request;
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \exface\Core\Interfaces\WorkbenchDependantInterface::getWorkbench()
     */
    public function getWorkbench()
    {
        return $this->connection->getWorkbench();
    }

    /**
     * 
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface::getCredentialsUxon()
     */
    public function getCredentialsUxon(AuthenticationTokenInterface $authenticatedToken): UxonObject
    {
        if (! $authenticatedToken instanceof OAuth2AuthenticatedToken) {
            throw new InvalidArgumentException('Cannot store authentication token ' . get_class($authenticatedToken) . ' in OAuth2 credentials: only OAuth2AuthenticatedToken or derivatives supported!');
        }
        
        $accessToken = $authenticatedToken->getAccessToken();
        $uxon = new UxonObject([
            'authentication' => [
                'class' => '\\' . get_class($this),
                'token' => $accessToken->jsonSerialize(),
                'refresh_token' => $accessToken->getRefreshToken() ? $accessToken->getRefreshToken() : $this->getRefreshToken($accessToken)
            ]
        ]);
        
        return $uxon;
    }
    
    protected function setToken(UxonObject $uxon) : MicrosoftOAuth2
    {
        $this->storedToken = new AccessToken($uxon->toArray());
        return $this;
    }
    
    protected function getTokenStored() : ?AccessTokenInterface
    {
        return $this->storedToken;
    }
    
    public function exportUxonObject()
    {
        return $this->originalUxon ?? new UxonObject();
    }
    
    protected function getRefreshToken(AccessTokenInterface $authenticatedToken) : ?string
    {
        return $this->refreshToken;
    }
    
    /**
     * 
     * @param string|null $value
     * @return MicrosoftOAuth2
     */
    protected function setRefreshToken($value) : MicrosoftOAuth2
    {
        $this->refreshToken = $value;
        return $this;
    }
    
    protected function getAuthProvider() : AuthenticationProviderInterface
    {
        return $this->getConnection();
    }
    
    /**
     *
     * {@inheritDoc}
     * @see \exface\UrlDataConnector\Interfaces\HttpAuthenticationProviderInterface::getConnection()
     */
    public function getConnection() : HttpConnectionInterface
    {
        return $this->connection;
    }
}