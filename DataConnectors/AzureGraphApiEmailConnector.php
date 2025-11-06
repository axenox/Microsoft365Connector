<?php
namespace axenox\Microsoft365Connector\DataConnectors;

use exface\Core\DataConnectors\SmtpConnector;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Vitrus\SymfonyOfficeGraphMailer\Transport\GraphApiTransportFactory;

/**
 * Connector to send emails 
 */
class AzureGraphApiEmailConnector extends SmtpConnector
{


    /**
     *
     * @return TransportInterface
     */
    protected function getTransport() : TransportInterface
    {
        $transport = (new GraphApiTransportFactory())->create($this->getDsn());
        return $transport;
    }

    /**
     *
     * @return string
     */
    protected function getScheme() : string
    {
        return 'microsoft-graph-api://';
    }

    /**
     * Azure client id
     * 
     * @uxon-property client_id
     * @uxon-type string
     * 
     * @param string $clientId
     * @return AzureGraphApiEmailConnector
     */
    protected function setClientId(string $clientId) : AzureGraphApiEmailConnector
    {
        return $this->setUser($clientId);
    }

    /**
     * Azure client secret
     *
     * @uxon-property client_secret
     * @uxon-type string
     *
     * @param string $secret
     * @return AzureGraphApiEmailConnector
     */
    protected function setClientSecret(string $secret) : AzureGraphApiEmailConnector
    {
        return $this->setPassword($secret);
    }

    /**
     * Azure tenant
     *
     * @uxon-property tenant
     * @uxon-type string
     *
     * @param string $tenant
     * @return AzureGraphApiEmailConnector
     */
    protected function setTenant(string $tenant) : AzureGraphApiEmailConnector
    {
        return $this->setHost($tenant);
    }
}