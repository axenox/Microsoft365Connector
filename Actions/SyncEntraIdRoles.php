<?php
namespace axenox\Microsoft365Connector\Actions;

use axenox\Microsoft365Connector\CommonLogic\Security\Authenticators\MicrosoftOAuth2Authenticator;
use Exception;
use exface\Core\CommonLogic\AbstractAction;
use exface\Core\CommonLogic\DataSheets\DataCollector;
use exface\Core\CommonLogic\DataSheets\DataSheet;
use exface\Core\CommonLogic\Security\AuthenticationToken\RememberMeAuthToken;
use exface\Core\CommonLogic\Security\SecurityManager;
use exface\Core\CommonLogic\UxonObject;
use exface\Core\DataTypes\ComparatorDataType;
use exface\Core\DataTypes\DateTimeDataType;
use exface\Core\Exceptions\Actions\ActionConfigurationError;
use exface\Core\Factories\DataSheetFactory;
use exface\Core\Factories\ResultFactory;
use exface\Core\Factories\UserFactory;
use exface\Core\Interfaces\DataSources\DataTransactionInterface;
use exface\Core\Interfaces\Tasks\ResultInterface;
use exface\Core\Interfaces\Tasks\TaskInterface;

/**
 * It synchronizes the Azure EntraID roles and the mail of given users with the PowerUI.
 * If the user is not found or has the flag "accountEnabled" set to false in Azure, the action can either disable the user in PowerUI or just skip disabling.
 *
 * For detailed documentation please visit the [SyncEntraIdRoles documentation](https://github.com/axenox/Microsoft365Connector/blob/1.x-dev/Docs/SyncEntraIdRoles_documentation.md).
 * 
 * @author Andrej Kabachnik and Sergej Riel
 */
class SyncEntraIdRoles extends AbstractAction
{
    private ?string $authenticatorId = null;
    private bool $disabledAzureAuthenticatedUsers = false;
    private bool $useUserMailAsFallback = false;
    private bool $syncUserMail = false;

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
        $collector->addAttributeAlias('DISABLED_FLAG');
        $collector->addAttributeAlias('COMMENTS');
        $collector->addAttributeAlias('USER_AUTHENTICATOR__AUTHENTICATOR_USERNAME:LIST_DISTINCT');
        $collector->addAttributeAlias('USER_AUTHENTICATOR__AUTHENTICATOR_USERNAME:MAX_OF(LAST_AUTHENTICATED_ON)');
        $collector->addAttributeAlias('USER_AUTHENTICATOR__SYNC_MAIL_FLAG:MAX_OF(LAST_AUTHENTICATED_ON)');
        $collector->addAttributeAlias('USER_AUTHENTICATOR__AUTHENTICATOR:LIST_DISTINCT');
        $collector->enrich($usersData);
        
        $usersCount = $usersData->countRows();
        $usersSynced = 0;
        $userMailSynced = 0;
        $userMailSyncSkipped = 0;
        
        $usersDisabledOrSkippedDisabling = 0;
        
        $useUserMailAsFallback = $this->getUseUserMailAsFallback();
        $trySyncUserMail = $this->getSyncUserMail();
        
        // Authenticator username is used for authentication in Azure and is stored as userPrincipalName in Graph.
        $userAzureAuthUsernameCol = $usersData->getColumns()->getByExpression('USER_AUTHENTICATOR__AUTHENTICATOR_USERNAME:MAX_OF(LAST_AUTHENTICATED_ON)')->getName();
        $userAzureAuthCol = $usersData->getColumns()->getByExpression('USER_AUTHENTICATOR__AUTHENTICATOR:LIST_DISTINCT')->getName();
        $userAzureAuthSyncMailFlagCol = $usersData->getColumns()->getByExpression('USER_AUTHENTICATOR__SYNC_MAIL_FLAG:MAX_OF(LAST_AUTHENTICATED_ON)')->getName();
        
        $logbook = $this->getLogBook($task);
        $logbook->addLine('Using Azure Authenticator to search for each user by their Authenticator username.' 
            . ($useUserMailAsFallback ? ' If the username is missing or not found, using their in PowerUI saved email address as fallback.' : '') 
            . ' Then, sync roles' . ($trySyncUserMail ? ' and email (if the sync_mail_flag at the user authenticator is set to true' : '') . ' based on Azure groups or disable them if no active Azure user is found.');

        $logbook->addLine('Used settings:');
        $logbook->addIndent(1);
        $logbook->addLine('Using PowerUI Email as fallback: `' . ($useUserMailAsFallback ? 'TRUE' : 'FALSE') . '`');
        $logbook->addLine('Syncing PowerUI Email with Azure: `' . ($trySyncUserMail ? 'TRUE' : 'FALSE') . '`');
        $logbook->addLine('Strategy for missing active Azure account: `' . ($this->getDisabledAzureAuthenticatedUsers() ? 'DISABLING' : 'SKIP DISABLING') . '`');
        $logbook->addIndent(-1);
        
        $logbook->addLine('Syncing roles for `' . $usersCount . '` users:');
        $logbook->addLine('| PowerUI Username | Auth. Username'. (($useUserMailAsFallback || $trySyncUserMail)? ' / PowerUI Email' : '') . ' | Active Azure account ID | Action |');
        $logbook->continueLine("\n" . '| -------- | ----- | ------------- | ------ |');
        
        foreach ($usersData->getRows() as $row) {
            $username = $row['USERNAME'];
            
            if ($username === null) {
                $logbook->continueLine("\n" . '| no username found | | | **skipping** |');
                continue;
            }
            
            $logbook->continueLine("\n" . '| `' . $username . '` |');
            $user = UserFactory::createFromUsername($this->getWorkbench(), $username);
            $fakeToken = new RememberMeAuthToken($username);
            
            $azureUserSheet = DataSheetFactory::createFromObjectIdOrAlias($this->getWorkbench(), 'axenox.Microsoft365Connector.users');
            $azureUserSheet->getColumns()->addFromExpression('id');
            $azureUserSheet->getColumns()->addFromExpression('userPrincipalName');
            $azureUserSheet->getColumns()->addFromExpression('mail');
            $azureUserSheet->getColumns()->addFromExpression('accountEnabled');

            $userMailsRaw = $row['EMAIL'];
            $userMails = is_array($userMailsRaw) ? $userMailsRaw : [$userMailsRaw];

            $userAzureAuthUsername = $row[$userAzureAuthUsernameCol];
            $userAzureAuthSyncMailFlag = $row[$userAzureAuthSyncMailFlagCol];
            
            $userAuthenticators = explode(',',$row[$userAzureAuthCol]);
            
            $userMails = array_filter($userMails, function($userMail) {
                return !empty($userMail);
            });

            // Sync only users, that have the authenticator of this action as of their authentication ways.
            // This will give us ONLY users, that are remote-controlled by EntraID. Any user, that was created locally
            // (= does not have a corresponding USER_AUTHENTICATOR entry) will be ignored because these users are
            // controlled by the workbench. In particular, users, that were created automatically when logging in via
            // Azure will always have the USER_AUTHENTICATOR entry with the authenticator id, that created them.
            if(!in_array($this->getAuthenticatorId(), $userAuthenticators)) {
                $logbook->continueLine(' | no Azure Authenticator | skipping |');
                continue;
            }

            // If no Authenticator Username (called userPrincipalName in Azure) is given and mail fallback is disabled,
            // we have no way to find the user in Azure.
            // With mail fallback enabled, at least one mail address is needed or the sync will be skipped.
            if (empty($userAzureAuthUsername) && (! $useUserMailAsFallback || empty($userMails))) {
                $logbook->continueLine(($useUserMailAsFallback ? 'no Auth. Username or Email address' : 'no Auth. Username') . ' | | skipping |');
                continue;
            }

            // Auth. Username / PowerUI Email
            $userLookupValue = !empty($userAzureAuthUsername) ? '`' . $userAzureAuthUsername . '`' : '';
            $userLookupValue .= (($useUserMailAsFallback || $trySyncUserMail) && !empty($userMails)) ? ' / `' . implode(', ', $userMails) . '`' : '';
            $logbook->continueLine($userLookupValue . ' |');

            // First, we need to find the user in Azure Graph.
            // We will search for the user by their Authenticator Username (userPrincipalName) in Graph.
            if (! empty($userAzureAuthUsername)) {
                $this->readActiveAzureUserDataByFilterCondition($azureUserSheet,'userPrincipalName', $userAzureAuthUsername, false);
            }
            
            // If nothing is found, we try again with the user email (if $useUserMailAsFallback set to true).
            if ($useUserMailAsFallback && ($azureUserSheet->countRows() <= 0) && !empty($userMails)) {
                // Trying again with the mail:
                $this->readActiveAzureUserDataByFilterCondition($azureUserSheet,'mail', $userMails, true);

                // This case may happen, if one person has multiple accounts with the same email address AND the userPrincipalNames are wrong (maybe got changed in Azure).
                // In this case, we cannot be sure which one is the right one, so we skip syncing to avoid mistakes.
                if ($azureUserSheet->countRows() > 1) {
                    $logbook->continueLine(' **found multiple Accounts** | skipping |');
                    Continue;
                }
            }
            $azureUserId = $azureUserSheet->getCellValue('id', 0);
            
            if (empty($azureUserId)) {
                $logbook->continueLine(' **not found in Azure** |');
                if ($row['DISABLED_FLAG']) {
                    $logbook->continueLine(' disabled previously |');
                } else {
                    if ($this->getDisabledAzureAuthenticatedUsers()) {
                        $logbook->continueLine(' **DISABLING** |');
                        $disableSheet = DataSheetFactory::createFromObject($usersData->getMetaObject());
                        $disableSheet->addRow([
                            'UID' => $row['UID'],
                            'DISABLE_DATE' => DateTimeDataType::now(),
                            'MODIFIED_ON' => $row['MODIFIED_ON']
                        ]);
                        $disableSheet->dataUpdate(false);
                        $usersSynced++;
                    } else {
                        $logbook->continueLine(' **SKIP DISABLING** |');
                    }
                    $usersDisabledOrSkippedDisabling++;
                }
                continue;
            } else {
                $logbook->continueLine(' ' . $azureUserId . ' |');
            }
            
            // If the sync_user_mail (uxon property here) and the sync_mail_flag (attribute oh the exface.Core.USER_AUTHENTICATOR) is enabled,
            // syncing user mail with the mail in Azure.
            $azureUserMail = $azureUserSheet->getCellValue('mail', 0);
            if (!in_array($azureUserMail, $userMails)) {
                if ($trySyncUserMail && $userAzureAuthSyncMailFlag) {
                    
                    $this->syncUserMail($usersData, $azureUserMail, $row);
                    $logbook->continueLine(' **mail & **');
                    $userMailSynced++;
                } else {
                    $logbook->continueLine(' mail sync skipped, ');
                    $userMailSyncSkipped++;
                }
            }
            
            // azureUserId can now be used to fetch the user roles and sync them.
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
            $logbook->continueLine(' **roles synced** |');
            $usersSynced++;
        }
        // Logbook and Result Summary
        $logbook->addLine('Synchronized roles for `' . $usersSynced . ' / ' . $usersCount . '` users.');
        $resultSummary = 'Synchronized roles for ' . $usersSynced . ' / ' . $usersCount . ' users. ';
        
        if ($userMailSynced > 0) {
            $logbook->addLine('Synchronized mails for `' . $userMailSynced . '` users.');
            $resultSummary .= 'Synchronized mails for ' . $userMailSynced . ' users. ';
        }
        if ($userMailSyncSkipped > 0) {
            $logbook->addLine('Email synchronisation was skipped for `' . $userMailSyncSkipped . '` users.');
            $resultSummary .= 'Email synchronisation was skipped for ' . $userMailSyncSkipped . ' users. ';
        }
        $logbook->addLine(($this->getDisabledAzureAuthenticatedUsers() ? 'Disabled' : 'Disabling was skipped for') . ' `' . $usersDisabledOrSkippedDisabling . '` of the users.');
        $resultSummary .= ($this->getDisabledAzureAuthenticatedUsers() ? 'Disabled ' : 'Disabling was skipped for ') . $usersDisabledOrSkippedDisabling . ' of the users.';
        
        return ResultFactory::createDataResult($task, $usersData, $resultSummary);
    }

    /**
     * Reads active Azure user data with given search values and flush filter if needed.
     *
     * @param DataSheet $azureUserSheet
     * @param string $azureValue
     * @param array|string $searchValueList
     * @param bool $flushFilter
     */
    private function readActiveAzureUserDataByFilterCondition(
        DataSheet $azureUserSheet,
        string $azureValue,
        array | string $searchValueList,
        bool $flushFilter
    ) : void
    {
        if ($flushFilter) {
            $azureUserSheet->getFilters()->removeAll();
        }

        $conditionGroup = $azureUserSheet->getFilters()->addNestedAND();
        $conditionGroup->addConditionFromString('accountEnabled', 'true', ComparatorDataType::EQUALS);
        $conditionGroup->addConditionFromValueArray($azureValue, $searchValueList);
        $azureUserSheet->dataRead();
    }

    /**
     * Syncs powerUI Email with the Azure mail.
     *
     * @param $usersData
     * @param $azureUserMail
     * @param $row
     * @return void
     * @throws Exception
     */
    private function syncUserMail($usersData, $azureUserMail, $row) : void
    {
        $userMailUpdateSheet = DataSheetFactory::createFromObject($usersData->getMetaObject());
        $userMailUpdateSheet->addRow([
            'UID' => $row['UID'],
            'EMAIL' => $azureUserMail,
            'MODIFIED_ON' => $row['MODIFIED_ON']
        ]);
        $userMailUpdateSheet->dataUpdate(false);
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

    /**
     * @return bool
     */
    protected function getDisabledAzureAuthenticatedUsers() : bool
    {
        return $this->disabledAzureAuthenticatedUsers;
    }

    /**
     * Set to TRUE to disable workbench users with Azure Authenticator if no active Azure account could be found!
     * Set to FALSE to just skip disabling in PowerUI. In this case, PowerUI users with present authentication entries, that can not be found in Azure or are disabled in Azure will remain active in PowerUI.
     * You can also set this property to false for testing purposes to see which users would be affected without actually disabling them.
     * 
     * @uxon-property disabled_azure_authenticated_users
     * @uxon-type boolean
     * @uxon-default false
     * 
     * @param bool $trueOrFalse
     * @return $this
     */
    protected function setDisabledAzureAuthenticatedUsers(bool $trueOrFalse) : SyncEntraIdRoles
    {
        $this->disabledAzureAuthenticatedUsers = $trueOrFalse;
        return $this;
    }

    /**
     * @return bool
     */
    protected function getUseUserMailAsFallback() : bool
    {
        return $this->useUserMailAsFallback;
    }

    /**
     * Set to TRUE to use the workbench user mail as fallback to find the user in Azure if the Authenticator Username (userPrincipalName) is missing or not found in Azure.
     * 
     * @uxon-property use_user_mail_as_fallback
     * @uxon-type boolean
     * @uxon-default false
     * 
     * @param bool $trueOrFalse
     * @return $this
     */
    protected function setUseUserMailAsFallback(bool $trueOrFalse) : SyncEntraIdRoles
    {
        $this->useUserMailAsFallback = $trueOrFalse;
        return $this;
    }

    /**
     * @return bool
     */
    protected function getSyncUserMail() : bool
    {
        return $this->syncUserMail;
    }

    /**
     * Set to TRUE to sync the user mail in PowerUI with the mail in Azure. 
     * If the mail in Azure is different from the one in PowerUI, it will be updated in PowerUI.
     * 
     * @uxon-property sync_user_mail
     * @uxon-type boolean
     * @uxon-default false
     * 
     * @param bool $trueOrFalse
     * @return $this
     */
    protected function setSyncUserMail(bool $trueOrFalse) : SyncEntraIdRoles
    {
        $this->syncUserMail = $trueOrFalse;
        return $this;
    }
}