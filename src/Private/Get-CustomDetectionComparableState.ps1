function Get-CustomDetectionComparableState {
    <#
    .SYNOPSIS
        Projects a detection rule into a canonical shape for change detection.

    .DESCRIPTION
        Works for the local request body and for rules returned by the Graph
        API, whether they carry the legacy properties, the current properties
        or both. Legacy values are translated so both sides compare on the
        same fields. Collections are sorted so ordering never counts as a change.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [PSObject]$Rule
    )

    function Get-Value {
        param([object]$Object, [string]$Path)
        $current = $Object
        foreach ($segment in $Path.Split('.')) {
            if ($null -eq $current) { return $null }
            $map = ConvertTo-CustomDetectionHashtable -InputObject $current
            if ($null -eq $map) { return $null }
            if (-not $map.Contains($segment)) { return $null }
            $current = $map[$segment]
        }
        return $current
    }

    function Get-Text {
        param([object]$Value)
        if ($null -eq $Value) { return '' }
        return "$Value"
    }

    function Test-HasItems {
        param([object]$Value)
        if ($null -eq $Value) { return $false }
        $map = ConvertTo-CustomDetectionHashtable -InputObject $Value
        if ($null -eq $map) { return $false }
        foreach ($key in $map.Keys) {
            $item = $map[$key]
            if ($null -ne $item -and @($item).Count -gt 0) { return $true }
        }
        return $false
    }

    function ConvertTo-SortedObject {
        param([object]$Value)
        if ($null -eq $Value) { return $null }
        $map = ConvertTo-CustomDetectionHashtable -InputObject $Value
        if ($null -ne $map) {
            $sorted = [ordered]@{}
            foreach ($key in ($map.Keys | Sort-Object)) {
                $sorted[$key] = ConvertTo-SortedObject -Value $map[$key]
            }
            return $sorted
        }
        if ($Value -isnot [string] -and $Value -is [System.Collections.IEnumerable]) {
            $items = @($Value | ForEach-Object { ConvertTo-SortedObject -Value $_ })
            $sortedItems = @($items | Sort-Object -Property { $_ | ConvertTo-Json -Compress -Depth 10 })
            return , $sortedItems
        }
        return $Value
    }

    function ConvertTo-SortedJson {
        param([object]$Value)
        if ($null -eq $Value) { return '' }
        $sorted = ConvertTo-SortedObject -Value $Value
        if ($null -eq $sorted) { return '' }
        return ($sorted | ConvertTo-Json -Compress -Depth 10)
    }

    $status = Get-Value -Object $Rule -Path 'status'
    if ([string]::IsNullOrWhiteSpace("$status")) {
        $status = ConvertTo-CustomDetectionStatus -IsEnabled (Get-Value -Object $Rule -Path 'isEnabled')
    }

    $frequencySource = Get-Value -Object $Rule -Path 'schedule.frequency'
    if ([string]::IsNullOrWhiteSpace("$frequencySource")) {
        $frequencySource = Get-Value -Object $Rule -Path 'schedule.period'
    }
    $frequency = ''
    if (-not [string]::IsNullOrWhiteSpace("$frequencySource")) {
        try {
            $frequency = ConvertTo-CustomDetectionFrequency -Value $frequencySource
        } catch {
            # An unrecognised remote value still has to compare, so keep it verbatim
            $frequency = "$frequencySource".Trim().ToUpperInvariant()
        }
    }

    $tacticsSource = Get-Value -Object $Rule -Path 'detectionAction.alertTemplate.tactics'
    $tactics = $null
    if ($null -ne $tacticsSource -and @($tacticsSource).Count -gt 0) {
        $tactics = @(ConvertTo-CustomDetectionTactics -Tactics $tacticsSource)
    } else {
        $category = Get-Value -Object $Rule -Path 'detectionAction.alertTemplate.category'
        $techniques = Get-Value -Object $Rule -Path 'detectionAction.alertTemplate.mitreTechniques'
        if (-not [string]::IsNullOrWhiteSpace("$category")) {
            $tactics = @(ConvertTo-CustomDetectionTactics -Category "$category" -Techniques @($techniques))
        }
    }

    $entityMappingsSource = Get-Value -Object $Rule -Path 'detectionAction.alertTemplate.entityMappings'
    $entityMappings = $null
    if (Test-HasItems -Value $entityMappingsSource) {
        $entityMappings = ConvertFrom-CustomDetectionEntityMappings -EntityMappings $entityMappingsSource
    } else {
        $impactedAssets = Get-Value -Object $Rule -Path 'detectionAction.alertTemplate.impactedAssets'
        if ($null -ne $impactedAssets -and @($impactedAssets).Count -gt 0) {
            $entityMappings = ConvertFrom-CustomDetectionEntityMappings -ImpactedAssets @($impactedAssets)
        }
    }

    $automatedActionsSource = Get-Value -Object $Rule -Path 'detectionAction.automatedActions'
    $actions = @()
    if (Test-HasItems -Value $automatedActionsSource) {
        $actions = @(ConvertFrom-CustomDetectionAutomatedActions -AutomatedActions $automatedActionsSource -WarningAction SilentlyContinue)
    } else {
        $responseActions = Get-Value -Object $Rule -Path 'detectionAction.responseActions'
        if ($null -ne $responseActions -and @($responseActions).Count -gt 0) {
            $translated = ConvertTo-CustomDetectionAutomatedActions -ResponseActions @($responseActions)
            $actions = @(ConvertFrom-CustomDetectionAutomatedActions -AutomatedActions $translated -WarningAction SilentlyContinue)
        }
    }

    $scopeSource = Get-Value -Object $Rule -Path 'detectionAction.organizationalScope'
    $deviceGroups = @()
    if ($null -ne $scopeSource) {
        $scopeMap = ConvertTo-CustomDetectionHashtable -InputObject $scopeSource
        if ($null -ne $scopeMap) {
            if ($scopeMap.Contains('deviceGroups') -and $null -ne $scopeMap['deviceGroups']) {
                $deviceGroups = @($scopeMap['deviceGroups'])
            } elseif ($scopeMap.Contains('scopeNames') -and $null -ne $scopeMap['scopeNames']) {
                $deviceGroups = @($scopeMap['scopeNames'])
            }
        } elseif ($scopeSource -isnot [string]) {
            $deviceGroups = @($scopeSource)
        } else {
            $deviceGroups = @($scopeSource)
        }
    }

    $customDetails = [ordered]@{}
    $customDetailsSource = ConvertTo-CustomDetectionHashtable -InputObject (Get-Value -Object $Rule -Path 'detectionAction.alertTemplate.customDetails')
    if ($null -ne $customDetailsSource) {
        foreach ($key in ($customDetailsSource.Keys | Sort-Object)) {
            $value = $customDetailsSource[$key]
            if ($null -ne $value -and "$value" -ne '') {
                $customDetails[$key] = "$value"
            }
        }
    }

    return [ordered]@{
        displayName        = Get-Text (Get-Value -Object $Rule -Path 'displayName')
        status             = Get-Text $status
        description        = Get-Text (Get-Value -Object $Rule -Path 'description')
        frequency          = $frequency
        queryText          = Get-Text (Get-Value -Object $Rule -Path 'queryCondition.queryText')
        title              = Get-Text (Get-Value -Object $Rule -Path 'detectionAction.alertTemplate.title')
        alertDescription   = Get-Text (Get-Value -Object $Rule -Path 'detectionAction.alertTemplate.description')
        severity           = (Get-Text (Get-Value -Object $Rule -Path 'detectionAction.alertTemplate.severity')).ToLowerInvariant()
        recommendedActions = Get-Text (Get-Value -Object $Rule -Path 'detectionAction.alertTemplate.recommendedActions')
        tactics            = ConvertTo-SortedJson -Value $tactics
        entityMappings     = ConvertTo-SortedJson -Value $entityMappings
        customDetails      = ConvertTo-SortedJson -Value $customDetails
        automatedActions   = ConvertTo-SortedJson -Value $actions
        deviceGroups       = ConvertTo-SortedJson -Value @($deviceGroups | ForEach-Object { "$_" } | Sort-Object)
    }
}
