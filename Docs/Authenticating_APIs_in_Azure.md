# Authenticating APIs in Azure

## Authentication via AppRegistration tokens

```mermaid
flowchart LR
    Users[Users]
    ExternaAPIs[External APIs]
    EntraID[Azure Entra ID]
    APIM[APIM]
    AppService[Azure AppService]
    
    ExternaAPIs -->|client_id, client_secret, scopes, SubscrKey| EntraID
    EntraID -->|JWT Token| ExternaAPIs
    ExternaAPIs -->|JWT Token| APIM
    ExternaAPIs -.->|JWT Token| AppService
    Users -->|OAuth2 Token| AppService
    Users -->|Login| EntraID
    EntraID -->|OAuth2 Token| Users

    subgraph Azure
        APIM -->|SubscrKey + JWT Token| AppService
    end
    
    style EntraID fill:#FFF,stroke:#104581
    style Users fill:#3CCBF4
    style ExternaAPIs fill:#3CCBF4
```

## Authentication via TLS certificates

The APIM supports mutual TLS authentication. It can validate provided certificats, but does not pass those further to
the AppService. This makes it difficult to securely identifiy APIM requests and those from "outside". It also requires
a simplified authentication for APIM requests just via subscription key. But since we can't identify APIM requests, we
are forced to allow subscription key authentication for ALL requests.

```mermaid
flowchart LR
    Users[Users]
    ExternaAPIs[External APIs]
    EntraID[Azure Entra ID]
    APIM[APIM]
    AppService[Azure AppService]
    
    ExternaAPIs -->|SubscrKey, Cert| APIM
    APIM -->|Validate Certs| EntraID
    ExternaAPIs -.->|BasicAuth, anything else| AppService
    Users -->|OAuth2| AppService

    subgraph Azure
        APIM -->|SubscrKey + IP filter| AppService
    end

    style EntraID fill:#FFF,stroke:#104581
    style Users fill:#3CCBF4
    style ExternaAPIs fill:#3CCBF4
```