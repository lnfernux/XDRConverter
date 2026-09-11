function Clear-CustomDetectionIdsCache {
    <#
    .SYNOPSIS
        Empties the cached detection id list.

    .DESCRIPTION
        Called after a rule is created or deleted so the next lookup
        queries the API instead of serving stale ids.
    #>
    [CmdletBinding()]
    param()

    # The time of the last list failure survives, a create or a delete says nothing about the list
    $script:DetectionIdsCache = @{
        Data      = $null
        ExpiresAt = [datetime]::MinValue
        FailedAt  = $script:DetectionIdsCache.FailedAt
    }
}
