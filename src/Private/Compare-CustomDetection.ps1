function Compare-CustomDetection {
    <#
    .SYNOPSIS
        Compares a local detection rule body against the remote rule.

    .DESCRIPTION
        Both sides are projected into the same canonical shape, so legacy and
        current property names compare as equals and collection order is
        ignored. Returns $true when any managed property differs.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [PSObject]$Local,

        [Parameter(Mandatory)]
        [PSObject]$Remote
    )

    $localState = Get-CustomDetectionComparableState -Rule $Local
    $remoteState = Get-CustomDetectionComparableState -Rule $Remote

    # Enumerations and device group names are matched by the API without case. Everything else, column names included, is case-sensitive
    $caseInsensitiveKeys = @('status', 'severity', 'tactics', 'deviceGroups')

    foreach ($key in $localState.Keys) {
        $localValue = "$($localState[$key])"
        $remoteValue = "$($remoteState[$key])"
        if ($localValue -eq '[]' -or $localValue -eq '{}') { $localValue = '' }
        if ($remoteValue -eq '[]' -or $remoteValue -eq '{}') { $remoteValue = '' }

        # The API offers no way to clear custom details, so an unset local value is not a change
        if ($key -eq 'customDetails' -and $localValue -eq '' -and $remoteValue -ne '') {
            Write-Warning "The rule carries customDetails that the file does not set. The API cannot remove them, so they stay: $remoteValue"
            continue
        }

        # A description or recommended action the file does not set stays on the rule. The update omits the property, so reporting it would repeat on every run
        if ($key -in @('description', 'recommendedActions') -and $localValue -eq '' -and $remoteValue -ne '') {
            Write-Verbose "The rule carries a $key that the file does not set. It is left unchanged."
            continue
        }

        $differs = if ($key -in $caseInsensitiveKeys) { $localValue -ne $remoteValue } else { $localValue -cne $remoteValue }
        if ($differs) {
            Write-Verbose "Difference found on '$key': local='$localValue' remote='$remoteValue'"
            return $true
        }
    }

    return $false
}
