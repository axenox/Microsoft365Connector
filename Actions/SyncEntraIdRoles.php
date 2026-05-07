<?php
namespace axenox\Microsoft365Connector\Actions;

use axenox\Microsoft365Connector\CommonLogic\Security\Authenticators\AzureAppRegistrationAuthenticator;
use axenox\Microsoft365Connector\CommonLogic\Security\Authenticators\MicrosoftOAuth2Authenticator;
use exface\Core\CommonLogic\AbstractAction;
use exface\Core\CommonLogic\DataSheets\DataCollector;
use exface\Core\CommonLogic\Security\AuthenticationToken\RememberMeAuthToken;
use exface\Core\CommonLogic\Security\SecurityManager;
use exface\Core\CommonLogic\UxonObject;
use exface\Core\DataTypes\ComparatorDataType;
use exface\Core\Exceptions\Actions\ActionConfigurationError;
use exface\Core\Factories\DataSheetFactory;
use exface\Core\Factories\ResultFactory;
use exface\Core\Factories\UserFactory;
use exface\Core\Interfaces\DataSources\DataTransactionInterface;
use exface\Core\Interfaces\Tasks\ResultInterface;
use exface\Core\Interfaces\Tasks\TaskInterface;

/**
 * It synchronizes the Azure EntraID roles of given users with the PowerUI.
 * 
 * This is important if you are using single-sign-on with Azure via OAuth2 and syncing user roles with Azure groups
 * via MS Graph API as described [in the docs](https://github.com/axenox/Microsoft365Connector/blob/1.x-dev/Docs/Synchronizing_roles_via_Graph_API.md).
 * In this case, you will have a `MicrosoftOAuth2Autenticator` in your `System.config.json` with a configured
 * `sync_roles_with_data_sheet`. 
 * 
 * Roles are synced every time a user logs on. However, if the user does not, there is no sync. In particular, if a 
 * user is offboarded, his user roles would remain, although he will probably not be able to log on with SSO. This 
 * action allows to force-sync roles for any selected user even without a log-in process. Syncing will be done exactly 
 * the same way as when logging in.
 * 
 * To make this work, the action should know which authenticator it should sync: place the id of the `MicrosoftOAuth2Autenticator` 
 * authenticator from `System.config.json` into the actions `authenticator_id` property. When the action is triggered,
 * it will read user data from the metaobjects `axenox.Microsoft365Connector.users` and `axenox.Microsoft365Connector.userGroups`
 * and will use the authenticator sync logic with this data.
 * 
 * ## Requirements
 * 
 * - `MicrosoftOAuth2Autenticator` authenticator with configured `sync_roles_with_data_sheet` in `System.config.json`.
 * - "Synchronized external user roles/groups" configured in `Administration > Users&Security > User Roles `
 * - If you want to sync roles in background: "app-only access" configured in the Azure App Registration for 
 * MS Graph API with permission `Directory.Read.All`.
 * 
 * ## Azure Graph API authorization
 * 
 * **NOTE:** reading the above Graph API object requires MS Graph authorization. When the regular on-login sync happens,
 * this authorization is done via "delegated access" with the same token the user just received through the 
 * single-sign-on process. However, if syncing with this action, the user who presses the button needs to be able to 
 * access MS Graph API.
 * 
 * Read more about [Accessing Azure APIs here](https://github.com/axenox/Microsoft365Connector/blob/1.x-dev/Docs/Accessing_other_services_and_APIs_in_Azure.md).
 * 
 * ### Syncing user roles manually
 * 
 * If it is a human user, who presses the button it should not be a problem as long as this user has logged in using
 * single-sign-on. Graph API will be called using "delegated access". At the time of logging in, the user was already 
 * authenticated in MS Graph to perform the regular sync. Now this authorization will be reused automatically. 
 * 
 * The corresponding Azure app registration needs the permission `User.Read.All` for the regular sync to work and this 
 * should also be enough to sync the roles of a different user with this action.
 * 
 * ### Syncing roles in a background process
 * 
 * When syncing with this action from a background process there is no single-sign-on user active, so we must have
 * a connection configuration for "app-only" access to MS Graph. The data source `axenox.Microsoft365Connector.MICROSOFT_GRAPH`
 * must then have a connection with `AzureAppRegistrationAuth` authentication configured:
 * 
 * ```
 *  {
 *      "authentication": {
 *          "class": "\\axenox\\Microsoft365Connector\\DataConnectors\\Authentication\\AzureAppRegistrationAuth",
 *          "client_id": "...",
 *          "client_secret": ".",
 *          "tenant": "...",
 *          "scope": "https://graph.microsoft.com/.default"
 *      }
 *  }
 * 
 * ```
 * 
 * The `client_id`, `client_secret`, etc. are to be found in your app registration. You can use the same app registration
 * for single-sign-on and this app-only authentication. However, the app-only authentication requires a different
 * permission: `Directory.Read.All`. The permission `User.Read.All` is not enough here.
 */
class SyncEntraIdRoles extends AbstractAction
{
    private ?string $authenticatorId = null;

    /**
     * @inheritDoc
     */
    protected function perform(TaskInterface $task, DataTransactionInterface $transaction): ResultInterface
    {
        $authenticator = SecurityManager::loadAuthenticatorsFromConfig($this->getWorkbench())[$this->getAuthenticatorId()];

        if (! $authenticator instanceof MicrosoftOAuth2Authenticator) {
            throw new ActionConfigurationError($this, 'Invalid authenticator selected to sync EntraID roles');
        }
        
        // DataSheet with user UID per row
        $usersData = $this->getInputDataSheet($task);
        
        // Make sure, the data has the username as column
        $collector = new DataCollector($usersData->getMetaObject());
        $collector->addAttributeAlias('USERNAME');
        $collector->addAttributeAlias('EMAIL');
        $collector->enrich($usersData);
        
        $logbook = $this->getLogBook($task);
        $logbook->addLine('Syncing roles for `' . $usersData->countRows() . '` rows');
        $logbook->addIndent(+1);
        
        foreach ($usersData->getRows() as $row) {
            $username = $row['USERNAME'];
            $logbook->addLine('Syncing roles for `' . $username . '`');
            $user = UserFactory::createFromUsername($this->getWorkbench(), $username);
            $fakeToken = new RememberMeAuthToken($username);
            
            $azureUserSheet = DataSheetFactory::createFromObjectIdOrAlias($this->getWorkbench(), 'axenox.Microsoft365Connector.users');
            $azureUserSheet->getColumns()->addFromExpression('userPrincipalName');
            $azureUserSheet->getColumns()->addFromExpression('mail');

            $userMailsRaw = $row['EMAIL'];
            $userMails = is_array($userMailsRaw) ? $userMailsRaw : [$userMailsRaw];
            
            $userMails = array_filter($userMails, function($userMail) {
                return !empty($userMail);
            });

            if (empty($userMails)) {
                $logbook->continueLine(' -no Email address found - **skipping**!');
                // No sync if there is no email address available for the user.
                // TODO continue instead of return?
                return ResultFactory::createEmptyResult($task);
            }

            $logbook->continueLine('with emails `' . implode(', ', $userMails) . '`');
            $logbook->addIndent(+1);

            $conditionGroup = $azureUserSheet->getFilters()->addNestedOR();
            $conditionGroup->addConditionFromValueArray('userPrincipalName', $userMails);
            $conditionGroup->addConditionFromValueArray('mail', $userMails);

            $azureUserSheet->dataRead();
            $azureUserId = $azureUserSheet->getCellValue('id', 0);
            
            $authenticator->importUxonObject(new UxonObject([
                "sync_roles_with_data_sheet" => [
                    "object_alias" => "axenox.Microsoft365Connector.userGroups",
                    "columns" => [
                        [
                            "attribute_alias" => "id"
                        ]
                    ],
                    "filters" => [
                        "operator" => EXF_LOGICAL_AND,
                        "conditions" => [
                            [
                                "attribute_alias" => "user_id",
                                "comparator" => ComparatorDataType::EQUALS,
                                "value" => $azureUserId
                            ]
                        ]
                    ]
                ]
            ]));
            $authenticator->syncUserRoles($user, $fakeToken);
            $logbook->addIndent(-1);
        }
        return ResultFactory::createDataResult($task, $usersData, 'Sync successful');
    }

    /**
     * Id of the authenticator in System.config.json
     * 
     * @uxon-property authenticator_id
     * @uxon-type string
     * 
     * @param string $id
     * @return $this
     */
    protected function setAuthenticatorId(string $id) : SyncEntraIdRoles
    {
        $this->authenticatorId = $id;
        return $this;
    }

    /**
     * @return string
     */
    protected function getAuthenticatorId() : string
    {
        return $this->authenticatorId;
    }
}