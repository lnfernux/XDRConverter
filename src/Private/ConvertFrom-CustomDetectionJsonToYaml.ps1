function ConvertFrom-CustomDetectionJsonToYaml {
    <#
    .SYNOPSIS
        Converts a Graph API detection rule into the YAML rule shape.

    .DESCRIPTION
        Emits the current YAML keys (tactics, entityMappings, customDetails,
        ISO 8601 frequency, description). Rules that still carry the legacy
        properties (category, mitreTechniques, impactedAssets, responseActions,
        period, isEnabled) are translated so the output always uses the current
        keys. Read-only and runtime properties are dropped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSObject]$JsonObject,

        [Parameter()]
        [bool]$SetEnabled,

        [Parameter()]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$SetSeverity
    )

    $DefaultSortOrderInYAML = @(
        'guid'
        'ruleName'
        'description'
        'isEnabled'
        'status'
        'alertTitle'
        'frequency'
        'alertSeverity'
        'alertDescription'
        'alertRecommendedAction'
        'tactics'
        'entityMappings'
        'customDetails'
        'organizationalScope'
        'actions'
        'queryText'
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

    function Test-HasItems {
        param([object]$Value)
        $map = ConvertTo-CustomDetectionHashtable -InputObject $Value
        if ($null -eq $map) { return $false }
        foreach ($key in $map.Keys) {
            $item = $map[$key]
            if ($null -ne $item -and @($item).Count -gt 0) { return $true }
        }
        return $false
    }

    function Test-HasValue {
        param([object]$Value)
        if ($null -eq $Value) { return $false }
        if ($Value -is [string]) { return -not [string]::IsNullOrWhiteSpace($Value) }
        if ($Value -is [System.Collections.IDictionary]) { return $Value.Count -gt 0 }
        if ($Value -is [System.Collections.IEnumerable]) { return @($Value).Count -gt 0 }
        return $true
    }

    # Strip the description tag from the alert description
    $uuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $alertDescription = Get-Value -Object $JsonObject -Path 'detectionAction.alertTemplate.description'
    if ($alertDescription) {
        $alertDescription = ($alertDescription -replace "\s*\[(?:[^:\]]*:)?$uuidPattern\]", '').Trim()
    }

    # Keep the raw status here so an autoDisabled rule exports as such; the forward path maps it on deploy
    $rawStatus = "$(Get-Value -Object $JsonObject -Path 'status')".Trim()
    $status = if ($PSBoundParameters.ContainsKey('SetEnabled')) {
        ConvertTo-CustomDetectionStatus -IsEnabled $SetEnabled
    } elseif ($rawStatus -eq 'autoDisabled') {
        'autoDisabled'
    } else {
        ConvertTo-CustomDetectionStatus -IsEnabled (Get-Value -Object $JsonObject -Path 'isEnabled') -Status $rawStatus -WarningAction SilentlyContinue
    }

    $severity = if ($PSBoundParameters.ContainsKey('SetSeverity')) {
        $SetSeverity
    } else {
        $rawSeverity = Get-Value -Object $JsonObject -Path 'detectionAction.alertTemplate.severity'
        if ($rawSeverity) { (Get-Culture).TextInfo.ToTitleCase("$rawSeverity".ToLowerInvariant()) } else { $null }
    }

    $yamlObj = [ordered]@{
        guid             = Get-CustomDetectionIdentity -Rule $JsonObject
        ruleName         = Get-Value -Object $JsonObject -Path 'displayName'
        isEnabled        = ($status -eq 'enabled')
        alertTitle       = Get-Value -Object $JsonObject -Path 'detectionAction.alertTemplate.title'
        alertSeverity    = $severity
        alertDescription = $alertDescription
        queryText        = Get-Value -Object $JsonObject -Path 'queryCondition.queryText'
    }

    if ($status -notin @('enabled', 'disabled')) {
        $yamlObj['status'] = $status
    }

    $description = Get-Value -Object $JsonObject -Path 'description'
    if (Test-HasValue $description) {
        $yamlObj['description'] = $description
    }

    $frequencySource = Get-Value -Object $JsonObject -Path 'schedule.frequency'
    if (-not (Test-HasValue $frequencySource)) {
        $frequencySource = Get-Value -Object $JsonObject -Path 'schedule.period'
    }
    if (Test-HasValue $frequencySource) {
        $yamlObj['frequency'] = ConvertTo-CustomDetectionFrequency -Value $frequencySource
    }

    $recommendedActions = Get-Value -Object $JsonObject -Path 'detectionAction.alertTemplate.recommendedActions'
    if (Test-HasValue $recommendedActions) {
        $yamlObj['alertRecommendedAction'] = $recommendedActions
    }

    $tacticsSource = Get-Value -Object $JsonObject -Path 'detectionAction.alertTemplate.tactics'
    $tactics = @()
    if (Test-HasValue $tacticsSource) {
        $tactics = @(ConvertTo-CustomDetectionTactics -Tactics $tacticsSource)
    } else {
        $category = Get-Value -Object $JsonObject -Path 'detectionAction.alertTemplate.category'
        if (Test-HasValue $category) {
            $techniques = @(Get-Value -Object $JsonObject -Path 'detectionAction.alertTemplate.mitreTechniques' | Where-Object { $_ })
            $tactics = @(ConvertTo-CustomDetectionTactics -Category "$category" -Techniques $techniques)
        }
    }
    if ($tactics.Count -gt 0) {
        $yamlObj['tactics'] = [object[]]$tactics
    }

    $entityMappingsSource = Get-Value -Object $JsonObject -Path 'detectionAction.alertTemplate.entityMappings'
    $entityMappings = $null
    if (Test-HasItems -Value $entityMappingsSource) {
        $entityMappings = ConvertFrom-CustomDetectionEntityMappings -EntityMappings $entityMappingsSource
    } else {
        $impactedAssets = Get-Value -Object $JsonObject -Path 'detectionAction.alertTemplate.impactedAssets'
        if (Test-HasValue $impactedAssets) {
            $entityMappings = ConvertFrom-CustomDetectionEntityMappings -ImpactedAssets @($impactedAssets)
        }
    }
    if ($entityMappings) {
        $yamlObj['entityMappings'] = $entityMappings
    }

    $customDetailsSource = ConvertTo-CustomDetectionHashtable -InputObject (Get-Value -Object $JsonObject -Path 'detectionAction.alertTemplate.customDetails')
    if ($customDetailsSource -and $customDetailsSource.Count -gt 0) {
        $customDetails = [ordered]@{}
        foreach ($key in $customDetailsSource.Keys) {
            if (Test-HasValue $customDetailsSource[$key]) {
                $customDetails[[string]$key] = "$($customDetailsSource[$key])"
            }
        }
        if ($customDetails.Count -gt 0) {
            $yamlObj['customDetails'] = $customDetails
        }
    }

    $scopeSource = Get-Value -Object $JsonObject -Path 'detectionAction.organizationalScope'
    $deviceGroups = @()
    if ($null -ne $scopeSource) {
        $scopeMap = ConvertTo-CustomDetectionHashtable -InputObject $scopeSource
        if ($null -ne $scopeMap) {
            if (Test-HasValue $scopeMap['deviceGroups']) {
                $deviceGroups = @($scopeMap['deviceGroups'])
            } elseif (Test-HasValue $scopeMap['scopeNames']) {
                $deviceGroups = @($scopeMap['scopeNames'])
            }
        } else {
            $deviceGroups = @($scopeSource | Where-Object { $_ })
        }
    }
    if ($deviceGroups.Count -gt 0) {
        $yamlObj['organizationalScope'] = [object[]]@($deviceGroups | ForEach-Object { "$_" })
    }

    $automatedActionsSource = Get-Value -Object $JsonObject -Path 'detectionAction.automatedActions'
    $actions = @()
    if (Test-HasItems -Value $automatedActionsSource) {
        $actions = @(ConvertFrom-CustomDetectionAutomatedActions -AutomatedActions $automatedActionsSource)
    } else {
        $responseActions = Get-Value -Object $JsonObject -Path 'detectionAction.responseActions'
        if (Test-HasValue $responseActions) {
            $translated = ConvertTo-CustomDetectionAutomatedActions -ResponseActions @($responseActions)
            $actions = @(ConvertFrom-CustomDetectionAutomatedActions -AutomatedActions $translated)
        }
    }
    if ($actions.Count -gt 0) {
        $yamlObj['actions'] = [object[]]$actions
    }

    $orderedYamlObj = [ordered]@{}
    foreach ($key in $DefaultSortOrderInYAML) {
        if ($yamlObj.Contains($key)) {
            $orderedYamlObj[$key] = $yamlObj[$key]
        }
    }

    foreach ($key in $yamlObj.Keys) {
        if (-not $orderedYamlObj.Contains($key)) {
            $orderedYamlObj[$key] = $yamlObj[$key]
        }
    }

    return $orderedYamlObj
}
