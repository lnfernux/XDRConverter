function ConvertTo-CustomDetectionAutomatedActions {
    <#
    .SYNOPSIS
        Builds the detectionAction.automatedActions object.

    .DESCRIPTION
        Accepts the YAML actions list (actionType plus optional additionalFields)
        or the legacy Graph responseActions collection and returns a dictionary
        keyed by automatedActions collection, each holding a list of action items.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Actions')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(ParameterSetName = 'Actions')]
        [AllowNull()]
        [object[]]$Actions,

        [Parameter(ParameterSetName = 'ResponseActions')]
        [AllowNull()]
        [object[]]$ResponseActions
    )

    $actionMap = Get-CustomDetectionActionMap

    if ($PSCmdlet.ParameterSetName -eq 'ResponseActions') {
        $translated = [System.Collections.Generic.List[object]]::new()
        foreach ($responseAction in @($ResponseActions)) {
            $map = ConvertTo-CustomDetectionHashtable -InputObject $responseAction
            if (-not $map) { continue }
            $odataType = "$($map['@odata.type'])"
            $suffix = if ($odataType -match '([A-Za-z]+)$') { $Matches[1] } else { $odataType }
            $entry = $actionMap | Where-Object { $_.LegacyType -eq $suffix } | Select-Object -First 1
            if (-not $entry) {
                throw "Unsupported response action type '$odataType'."
            }
            $action = [ordered]@{ actionType = $entry.ActionType }
            if ($map['isolationType']) {
                $action.additionalFields = @{ isolationType = "$($map['isolationType'])" }
            }
            $translated.Add($action)
        }
        $Actions = $translated.ToArray()
    }

    $result = [ordered]@{}

    foreach ($action in @($Actions)) {
        $map = ConvertTo-CustomDetectionHashtable -InputObject $action
        if (-not $map) { continue }
        $actionType = "$($map['actionType'])".Trim()
        $entry = $actionMap | Where-Object { $_.ActionType -eq $actionType } | Select-Object -First 1
        if (-not $entry) {
            $supported = ($actionMap | ForEach-Object { $_.ActionType }) -join ', '
            throw "Unsupported response action type '$actionType'. Supported types are: $supported"
        }

        $item = [ordered]@{}
        foreach ($key in $entry.Defaults.Keys) {
            $item[$key] = $entry.Defaults[$key]
        }

        $additional = ConvertTo-CustomDetectionHashtable -InputObject $map['additionalFields']
        if ($additional) {
            foreach ($key in @($additional.Keys)) {
                if ("$key".StartsWith('@')) { continue }
                if ($key -notin $entry.Fields) {
                    throw "Field '$key' is not documented for action '$actionType'. Documented fields are: $($entry.Fields -join ', ')"
                }
            }
            $hasSha1 = $additional.Contains('sha1Column') -and "$($additional['sha1Column'])" -ne ''
            $hasSha256 = $additional.Contains('sha256Column') -and "$($additional['sha256Column'])" -ne ''
            if ($hasSha1 -and $hasSha256) {
                throw "Action '$actionType' names sha1Column and sha256Column. A file action carries one hash column."
            }
            # A file action carries one hash column, so an explicit sha256Column replaces the sha1Column default
            if ($hasSha256 -and -not $hasSha1 -and $item.Contains('sha1Column')) {
                $item.Remove('sha1Column')
            }
            foreach ($key in @($additional.Keys)) {
                $value = $additional[$key]
                if ($null -eq $value -or "$value" -eq '') { continue }
                if ($key -eq 'isolationType') {
                    $isolationType = "$value".ToLowerInvariant()
                    if ($isolationType -notin @('full', 'selective')) {
                        Write-Warning "Isolation type '$value' is not supported. Defaulting to 'Full'."
                        $isolationType = 'full'
                    }
                    $item[$key] = $isolationType
                } elseif ($key -eq 'deviceGroupNames') {
                    $item[$key] = [object[]]@($value)
                } else {
                    $item[$key] = $value
                }
            }
        }

        if (-not $result.Contains($entry.Collection)) {
            $result[$entry.Collection] = [System.Collections.Generic.List[object]]::new()
        }
        $result[$entry.Collection].Add($item)
    }

    if ($result.Count -eq 0) {
        return $null
    }

    foreach ($collection in @($result.Keys)) {
        $result[$collection] = [object[]]$result[$collection].ToArray()
    }

    return $result
}
