function ConvertFrom-CustomDetectionYamlToJson {
    <#
    .SYNOPSIS
        Converts a YAML detection rule into the Graph API request body.

    .DESCRIPTION
        Accepts both the legacy YAML keys (isEnabled, alertCategory,
        mitreTechniques, impactedEntities, period-style frequency) and the
        current keys (status, tactics, entityMappings, customDetails,
        description, ISO 8601 frequency). Legacy values are translated to the
        current Graph properties. When both forms are present the current key wins.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSObject]$YamlObject,

        [Parameter()]
        [bool]$SetEnabled,

        [Parameter()]
        [ValidateSet('Informational', 'Low', 'Medium', 'High')]
        [string]$SetSeverity,

        [Parameter()]
        [switch]$SkipIdentifierValidation
    )

    $knownKeys = @(
        'guid', 'id', 'ruleName', 'description', 'isEnabled', 'status', 'frequency', 'alertTitle',
        'alertSeverity', 'alertDescription', 'alertRecommendedAction', 'alertCategory', 'mitreTechniques',
        'tactics', 'impactedEntities', 'entityMappings', 'customDetails', 'organizationalScope', 'actions', 'queryText'
    )

    $yaml = ConvertTo-CustomDetectionHashtable -InputObject $YamlObject
    if ($null -eq $yaml) {
        throw 'The YAML input is not a detection rule object.'
    }

    foreach ($key in $yaml.Keys) {
        if ($key -notin $knownKeys) {
            Write-Warning "Unknown key '$key' is ignored."
        }
    }

    function Get-YamlValue {
        param([string]$Key)
        if ($yaml.Contains($Key)) { return $yaml[$Key] }
        return $null
    }

    function Test-HasValue {
        param([object]$Value)
        if ($null -eq $Value) { return $false }
        if ($Value -is [string]) { return -not [string]::IsNullOrWhiteSpace($Value) }
        if ($Value -is [System.Collections.IDictionary]) { return $Value.Count -gt 0 }
        if ($Value -is [System.Collections.IEnumerable]) { return @($Value).Count -gt 0 }
        return $true
    }

    # The guid and the id alias name the same rule, with or without the rule prefix the request carries
    $guid = Get-YamlValue -Key 'guid'
    $idAlias = Get-YamlValue -Key 'id'
    $bareGuid = if (Test-HasValue $guid) { "$guid".Trim() -replace '^rule-', '' } else { $null }
    $bareAlias = if (Test-HasValue $idAlias) { "$idAlias".Trim() -replace '^rule-', '' } else { $null }
    if ($bareGuid -and $bareAlias -and ($bareGuid -ne $bareAlias)) {
        throw "The guid '$guid' and id '$idAlias' differ. Use one of them."
    }
    $ruleGuid = if ($bareGuid) { $bareGuid } elseif ($bareAlias) { $bareAlias } else { $null }

    $status = if ($PSBoundParameters.ContainsKey('SetEnabled')) {
        ConvertTo-CustomDetectionStatus -IsEnabled $SetEnabled
    } else {
        ConvertTo-CustomDetectionStatus -IsEnabled (Get-YamlValue -Key 'isEnabled') -Status (Get-YamlValue -Key 'status')
    }

    $severity = if ($SetSeverity) {
        $SetSeverity
    } else {
        Get-YamlValue -Key 'alertSeverity'
    }
    if (-not (Test-HasValue $severity)) {
        throw 'The alertSeverity value is required. Use Informational, Low, Medium or High.'
    }

    $alertTemplate = [ordered]@{
        title       = Get-YamlValue -Key 'alertTitle'
        description = Get-YamlValue -Key 'alertDescription'
        severity    = "$severity".ToLowerInvariant()
    }

    $recommendedActions = Get-YamlValue -Key 'alertRecommendedAction'
    if (Test-HasValue $recommendedActions) {
        $alertTemplate.recommendedActions = $recommendedActions
    }

    $tacticsInput = Get-YamlValue -Key 'tactics'
    $category = Get-YamlValue -Key 'alertCategory'
    $techniques = Get-YamlValue -Key 'mitreTechniques'
    if ((Test-HasValue $tacticsInput) -and ((Test-HasValue $category) -or (Test-HasValue $techniques))) {
        Write-Verbose 'Both tactics and alertCategory/mitreTechniques are present. Using tactics.'
    }
    $tactics = @()
    if (Test-HasValue $tacticsInput) {
        $tactics = @(ConvertTo-CustomDetectionTactics -Tactics $tacticsInput)
    } elseif (Test-HasValue $category) {
        $tactics = @(ConvertTo-CustomDetectionTactics -Category "$category" -Techniques @($techniques))
    }
    if ($tactics.Count -eq 0) {
        throw 'The rule needs an alertCategory or a tactics list.'
    }
    if ($tactics.Count -gt 1) {
        throw "The rule lists $($tactics.Count) tactics. The API accepts a single tactic per rule."
    }
    $alertTemplate['tactics'] = [object[]]$tactics

    $entityMappingsInput = Get-YamlValue -Key 'entityMappings'
    $impactedEntities = Get-YamlValue -Key 'impactedEntities'
    $entityMappings = $null
    if (Test-HasValue $entityMappingsInput) {
        if (Test-HasValue $impactedEntities) {
            Write-Verbose 'Both entityMappings and impactedEntities are present. Using entityMappings.'
        }
        $entityMappings = ConvertTo-CustomDetectionEntityMappings -EntityMappings $entityMappingsInput -SkipIdentifierValidation:$SkipIdentifierValidation
    } elseif (Test-HasValue $impactedEntities) {
        $entityMappings = ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @($impactedEntities) -SkipIdentifierValidation:$SkipIdentifierValidation
    }
    if ($entityMappings) {
        $alertTemplate.entityMappings = $entityMappings
    }

    $customDetailsInput = ConvertTo-CustomDetectionHashtable -InputObject (Get-YamlValue -Key 'customDetails')
    if ($customDetailsInput -and $customDetailsInput.Count -gt 0) {
        if ($customDetailsInput.Count -gt 20) {
            throw "customDetails holds $($customDetailsInput.Count) entries. The limit is 20."
        }
        $customDetails = [ordered]@{}
        foreach ($key in $customDetailsInput.Keys) {
            $customDetails[[string]$key] = "$($customDetailsInput[$key])"
        }
        $alertTemplate.customDetails = $customDetails
    }

    $detectionAction = [ordered]@{
        alertTemplate = $alertTemplate
    }

    $scope = Get-YamlValue -Key 'organizationalScope'
    if (Test-HasValue $scope) {
        $deviceGroups = @($scope | ForEach-Object { "$_" })
        if (@($deviceGroups | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
            throw 'organizationalScope contains an empty device group name.'
        }
        $detectionAction['organizationalScope'] = [ordered]@{
            deviceGroups = [object[]]$deviceGroups
        }
    }

    $actions = Get-YamlValue -Key 'actions'
    if (Test-HasValue $actions) {
        $automatedActions = ConvertTo-CustomDetectionAutomatedActions -Actions @($actions)
        if ($automatedActions) {
            $detectionAction.automatedActions = $automatedActions
        }
    }

    $jsonObj = [ordered]@{}
    if ($ruleGuid) {
        $jsonObj.id = "rule-$ruleGuid"
    }
    $jsonObj.displayName = Get-YamlValue -Key 'ruleName'
    $jsonObj.status = $status

    $description = Get-YamlValue -Key 'description'
    if (Test-HasValue $description) {
        $jsonObj.description = $description
    }

    $jsonObj.queryCondition = [ordered]@{
        queryText = Get-YamlValue -Key 'queryText'
    }
    $jsonObj.schedule = [ordered]@{
        frequency = ConvertTo-CustomDetectionFrequency -Value (Get-YamlValue -Key 'frequency')
    }
    $jsonObj.detectionAction = $detectionAction

    return $jsonObj
}
