function ConvertTo-CustomDetectionEntityMappings {
    <#
    .SYNOPSIS
        Builds the alertTemplate.entityMappings object.

    .DESCRIPTION
        Accepts either the legacy impactedEntities list (entityType plus
        entityIdentifier) or an entityMappings object keyed by entity
        collection. Both return the Graph shape: a dictionary of collections,
        each holding a list of column mapping items.
    #>
    [CmdletBinding(DefaultParameterSetName = 'EntityMappings')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(ParameterSetName = 'ImpactedEntities')]
        [AllowNull()]
        [object[]]$ImpactedEntities,

        [Parameter(ParameterSetName = 'EntityMappings')]
        [AllowNull()]
        [object]$EntityMappings,

        [Parameter()]
        [switch]$SkipIdentifierValidation
    )

    $collectionColumns = Get-CustomDetectionEntityMappingColumns

    $legacyTypes = @{
        machine = @{ Collection = 'hosts'; DefaultColumn = 'nameColumn' }
        device  = @{ Collection = 'hosts'; DefaultColumn = 'nameColumn' }
        user    = @{ Collection = 'accounts'; DefaultColumn = 'nameColumn' }
        account = @{ Collection = 'accounts'; DefaultColumn = 'nameColumn' }
        mailbox = @{ Collection = 'mailboxes'; DefaultColumn = 'primaryAddressColumn' }
    }

    $legacyIdentifiers = Get-CustomDetectionLegacyIdentifierMap

    function Add-MappingColumn {
        param([System.Collections.Specialized.OrderedDictionary]$Result, [string]$Collection, [string]$Column, [string]$Value)

        if (-not $Result.Contains($Collection)) {
            $Result[$Collection] = [System.Collections.Generic.List[object]]::new()
        }
        $target = $Result[$Collection] | Where-Object { -not $_.Contains($Column) } | Select-Object -First 1
        if (-not $target) {
            $target = [ordered]@{}
            $Result[$Collection].Add($target)
        }
        $target[$Column] = $Value
    }

    $result = [ordered]@{}

    if ($PSCmdlet.ParameterSetName -eq 'ImpactedEntities') {
        foreach ($entity in @($ImpactedEntities)) {
            $map = ConvertTo-CustomDetectionHashtable -InputObject $entity
            if (-not $map) { continue }
            $entityType = "$($map['entityType'])".Trim()
            $identifier = "$($map['entityIdentifier'])".Trim()
            if (-not $entityType -or -not $identifier) {
                throw 'Each impactedEntities entry needs entityType and entityIdentifier.'
            }

            $typeInfo = $legacyTypes[$entityType.ToLowerInvariant()]
            if (-not $typeInfo) {
                throw "Entity type '$entityType' is not supported in impactedEntities. Use entityMappings for this entity."
            }

            $collection = $typeInfo.Collection
            $column = $null
            $canonical = $null
            foreach ($candidateColumn in $legacyIdentifiers[$collection].Keys) {
                $match = $legacyIdentifiers[$collection][$candidateColumn] | Where-Object { $_ -eq $identifier } | Select-Object -First 1
                if ($match) {
                    $column = $candidateColumn
                    $canonical = $match
                    break
                }
            }

            if (-not $column) {
                $validList = ($legacyIdentifiers[$collection].Values | ForEach-Object { $_ }) -join ', '
                if ($SkipIdentifierValidation) {
                    Write-Warning "Identifier '$identifier' for entity type '$entityType' is not in the official documentation. Valid identifiers are: $validList"
                    $column = $typeInfo.DefaultColumn
                    $canonical = $identifier
                } else {
                    throw "Invalid identifier '$identifier' for entity type '$entityType'. Valid identifiers are: $validList"
                }
            } elseif ($canonical -eq 'accountId') {
                Write-Warning "Identifier 'accountId' has no dedicated entity mapping column. Mapped to accounts.nameColumn."
            }

            $columnValue = $canonical.Substring(0, 1).ToUpperInvariant() + $canonical.Substring(1)
            Add-MappingColumn -Result $result -Collection $collection -Column $column -Value $columnValue
        }
    } else {
        $mappings = ConvertTo-CustomDetectionHashtable -InputObject $EntityMappings
        foreach ($key in @($mappings.Keys)) {
            $collection = $collectionColumns.Keys | Where-Object { $_ -eq $key } | Select-Object -First 1
            if (-not $collection) {
                $known = $collectionColumns.Keys -join ', '
                if ($SkipIdentifierValidation) {
                    Write-Warning "Unknown entity mapping '$key'. Known mappings are: $known"
                    $collection = $key
                } else {
                    throw "Unknown entity mapping '$key'. Known mappings are: $known"
                }
            }

            $rawItems = $mappings[$key]
            if ($null -eq $rawItems) { continue }
            if ($rawItems -is [string] -or $rawItems -isnot [System.Collections.IEnumerable] -or $rawItems -is [System.Collections.IDictionary]) {
                $rawItems = @($rawItems)
            }

            foreach ($rawItem in $rawItems) {
                $item = ConvertTo-CustomDetectionHashtable -InputObject $rawItem
                if (-not $item) { continue }
                $cleanItem = [ordered]@{}
                foreach ($columnKey in @($item.Keys)) {
                    if ("$columnKey".StartsWith('@')) { continue }
                    $value = $item[$columnKey]
                    if ($null -eq $value -or "$value" -eq '') { continue }
                    if ($collectionColumns.Contains($collection) -and $columnKey -notin $collectionColumns[$collection]) {
                        $validColumns = $collectionColumns[$collection] -join ', '
                        if ($SkipIdentifierValidation) {
                            Write-Warning "Column '$columnKey' is not documented for '$collection'. Documented columns are: $validColumns"
                        } else {
                            throw "Invalid column '$columnKey' for entity mapping '$collection'. Documented columns are: $validColumns"
                        }
                    }
                    $cleanItem[$columnKey] = $value
                }
                if ($cleanItem.Count -eq 0) { continue }
                if (-not $result.Contains($collection)) {
                    $result[$collection] = [System.Collections.Generic.List[object]]::new()
                }
                $result[$collection].Add($cleanItem)
            }
        }
    }

    # The API rejects an account mapping that has no key column and no name plus domain pair.
    # Legacy input is dropped with a warning, which is what the API did with impactedAssets.
    # Explicit input is an error unless validation is skipped.
    if ($result.Contains('accounts')) {
        $dropIncomplete = ($PSCmdlet.ParameterSetName -eq 'ImpactedEntities') -or $SkipIdentifierValidation
        $complete = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $result['accounts']) {
            $hasKeyColumn = $item.Contains('aadUserIdColumn') -or $item.Contains('sidColumn') -or $item.Contains('upnColumn')
            $hasNameAndDomain = $item.Contains('nameColumn') -and ($item.Contains('ntDomainColumn') -or $item.Contains('dnsDomainColumn') -or $item.Contains('upnSuffixColumn'))
            if ($hasKeyColumn -or $hasNameAndDomain) {
                $complete.Add($item)
                continue
            }
            $columns = ($item.Keys | ForEach-Object { "$_ = $($item[$_])" }) -join ', '
            $message = "Account mapping ($columns) needs aadUserIdColumn, sidColumn, upnColumn, or nameColumn together with a domain column."
            if (-not $dropIncomplete) {
                throw $message
            }
            Write-Warning "$message It is dropped."
        }
        if ($complete.Count -eq 0) {
            $result.Remove('accounts')
        } else {
            $result['accounts'] = $complete
        }
    }

    if ($result.Count -eq 0) {
        return $null
    }

    foreach ($collection in @($result.Keys)) {
        $result[$collection] = [object[]]$result[$collection].ToArray()
    }

    return $result
}
