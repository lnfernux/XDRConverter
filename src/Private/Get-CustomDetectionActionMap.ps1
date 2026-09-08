function Get-CustomDetectionActionMap {
    <#
    .SYNOPSIS
        Returns the table of supported automated actions.

    .DESCRIPTION
        Each entry links the YAML actionType to its automatedActions collection,
        the legacy responseAction type name and the default column mapping.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $deviceDefaults = [ordered]@{ deviceIdColumn = 'DeviceId' }
    # The API stores one hash column per file action, so only sha1Column is defaulted
    $fileDefaults = [ordered]@{ sha1Column = 'SHA1' }
    $sidDefaults = [ordered]@{ accountSidColumn = 'AccountSid' }
    $emailDefaults = [ordered]@{ networkMessageIdColumn = 'NetworkMessageId'; recipientColumn = 'RecipientEmailAddress' }

    return @(
        [PSCustomObject]@{ ActionType = 'IsolateMachine'; Collection = 'isolateDevices'; LegacyType = 'isolateDeviceResponseAction'; Defaults = [ordered]@{ deviceIdColumn = 'DeviceId'; isolationType = 'full' } }
        [PSCustomObject]@{ ActionType = 'CollectInvestigationPackage'; Collection = 'collectInvestigationPackages'; LegacyType = 'collectInvestigationPackageResponseAction'; Defaults = $deviceDefaults }
        [PSCustomObject]@{ ActionType = 'RunAntivirusScan'; Collection = 'runAntivirusScans'; LegacyType = 'runAntivirusScanResponseAction'; Defaults = $deviceDefaults }
        [PSCustomObject]@{ ActionType = 'InitiateInvestigation'; Collection = 'initiateInvestigations'; LegacyType = 'initiateInvestigationResponseAction'; Defaults = $deviceDefaults }
        [PSCustomObject]@{ ActionType = 'RestrictAppExecution'; Collection = 'restrictAppExecutions'; LegacyType = 'restrictAppExecutionResponseAction'; Defaults = $deviceDefaults }
        [PSCustomObject]@{ ActionType = 'StopAndQuarantineFile'; Collection = 'stopAndQuarantineFiles'; LegacyType = 'stopAndQuarantineFileResponseAction'; Defaults = [ordered]@{ deviceIdColumn = 'DeviceId'; sha1Column = 'SHA1' } }
        [PSCustomObject]@{ ActionType = 'AllowFile'; Collection = 'allowFiles'; LegacyType = 'allowFileResponseAction'; Defaults = $fileDefaults }
        [PSCustomObject]@{ ActionType = 'BlockFile'; Collection = 'blockFiles'; LegacyType = 'blockFileResponseAction'; Defaults = $fileDefaults }
        [PSCustomObject]@{ ActionType = 'DisableUser'; Collection = 'disableUsers'; LegacyType = 'disableUserResponseAction'; Defaults = $sidDefaults }
        [PSCustomObject]@{ ActionType = 'ForceUserPasswordReset'; Collection = 'forceUserPasswordResets'; LegacyType = 'forceUserPasswordResetResponseAction'; Defaults = $sidDefaults }
        [PSCustomObject]@{ ActionType = 'MarkUserAsCompromised'; Collection = 'markUsersAsCompromised'; LegacyType = 'markUserAsCompromisedResponseAction'; Defaults = [ordered]@{ accountObjectIdColumn = 'AccountObjectId' } }
        [PSCustomObject]@{ ActionType = 'HardDeleteEmail'; Collection = 'hardDeleteEmails'; LegacyType = 'hardDeleteResponseAction'; Defaults = $emailDefaults }
        [PSCustomObject]@{ ActionType = 'SoftDeleteEmail'; Collection = 'softDeleteEmails'; LegacyType = 'softDeleteResponseAction'; Defaults = $emailDefaults }
        [PSCustomObject]@{ ActionType = 'MoveEmailToInbox'; Collection = 'moveEmailsToInbox'; LegacyType = 'moveToInboxResponseAction'; Defaults = $emailDefaults }
        [PSCustomObject]@{ ActionType = 'MoveEmailToJunk'; Collection = 'moveEmailsToJunk'; LegacyType = 'moveToJunkResponseAction'; Defaults = $emailDefaults }
        [PSCustomObject]@{ ActionType = 'MoveEmailToDeletedItems'; Collection = 'moveEmailsToDeletedItems'; LegacyType = 'moveToDeletedItemsResponseAction'; Defaults = $emailDefaults }
    )
}
