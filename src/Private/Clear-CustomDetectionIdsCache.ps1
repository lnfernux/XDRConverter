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

    $script:DetectionIdsCache = @{
        Data      = $null
        ExpiresAt = [datetime]::MinValue
    }
}
