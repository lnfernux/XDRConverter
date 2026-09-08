function Complete-CustomDetectionPatchBody {
    <#
    .SYNOPSIS
        Builds the PATCH body from a full rule body.

    .DESCRIPTION
        The API keeps any collection that a PATCH omits, so an action, entity
        mapping, device group or custom detail removed from the YAML file would
        stay live. The PATCH body therefore names every automated action and
        entity mapping collection, sending an empty list for the unused ones,
        and sends empty device groups when none are set. Custom details are
        left out when unset because the API offers no way to clear them.
        The rule id is left out because it cannot change.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Body
    )

    $patch = [ordered]@{}
    foreach ($key in $Body.Keys) {
        if ($key -ne 'id') { $patch[$key] = $Body[$key] }
    }

    $detectionAction = [ordered]@{}
    foreach ($key in $Body['detectionAction'].Keys) {
        $detectionAction[$key] = $Body['detectionAction'][$key]
    }
    $patch['detectionAction'] = $detectionAction

    $alertTemplate = [ordered]@{}
    foreach ($key in $detectionAction['alertTemplate'].Keys) {
        $alertTemplate[$key] = $detectionAction['alertTemplate'][$key]
    }
    $detectionAction['alertTemplate'] = $alertTemplate

    $entityMappings = [ordered]@{}
    $existingMappings = $alertTemplate['entityMappings']
    foreach ($collection in (Get-CustomDetectionEntityMappingColumns).Keys) {
        if ($existingMappings -and $existingMappings.Contains($collection) -and $null -ne $existingMappings[$collection]) {
            $entityMappings[$collection] = [object[]]@($existingMappings[$collection])
        } else {
            $entityMappings[$collection] = [object[]]@()
        }
    }
    $alertTemplate['entityMappings'] = $entityMappings

    $automatedActions = [ordered]@{}
    $existingActions = $detectionAction['automatedActions']
    foreach ($entry in Get-CustomDetectionActionMap) {
        $collection = $entry.Collection
        if ($existingActions -and $existingActions.Contains($collection) -and $null -ne $existingActions[$collection]) {
            $automatedActions[$collection] = [object[]]@($existingActions[$collection])
        } else {
            $automatedActions[$collection] = [object[]]@()
        }
    }
    $detectionAction['automatedActions'] = $automatedActions

    if (-not $detectionAction.Contains('organizationalScope') -or $null -eq $detectionAction['organizationalScope']) {
        $detectionAction['organizationalScope'] = [ordered]@{ deviceGroups = [object[]]@() }
    }

    return $patch
}
