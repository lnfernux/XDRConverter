function Get-CustomDetectionIdByDetectorId {
    <#
    .SYNOPSIS
        Gets the detection rule ID by its guid.

    .DESCRIPTION
        Looks up a detection rule whose rule ID equals the given guid. Rules
        created before the guid was used as the rule ID are matched on their
        legacy detector ID while the API still returns it.

    .PARAMETER DetectorId
        The guid to look up. Matched against the rule ID and the legacy detector ID.

    .EXAMPLE
        Get-CustomDetectionIdByDetectorId -DetectorId "81fb771a-c57e-41b8-9905-63dbf267c13f"

        Returns the detection rule ID for the specified detector ID.

    .NOTES
        Requires the Microsoft.Graph.Authentication module and an active Graph API session.
        Use Connect-MgGraph before calling this function.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$DetectorId
    )

    begin {
        Assert-MgGraphConnection
    }

    process {
        try {
            # Leverage the cached detection IDs list
            $detectionIds = Get-CustomDetectionIds

            # Match the rule id first, in its plain and rule-prefixed forms, then the legacy detector id
            $detectionRule = $detectionIds | Where-Object { $_.Id -eq $DetectorId -or $_.Id -eq "rule-$DetectorId" -or $_.DetectorId -eq $DetectorId } | Select-Object -First 1

            if ($detectionRule) {
                return $detectionRule.Id
            } else {
                Write-Verbose "No detection rule found with detectorId: $DetectorId"
                return $null
            }
        } catch {
            Write-Error "Error querying Microsoft Graph API: $($_.Exception.Message)"
            throw
        }
    }
}

