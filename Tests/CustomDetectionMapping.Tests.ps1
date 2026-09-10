Describe 'CustomDetection mapping helpers' {

    BeforeAll {
        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'XDRConverter.psd1'
        Import-Module -Name $ModulePath -Force
    }

    AfterAll {
        Remove-Module -Name XDRConverter -Force -ErrorAction SilentlyContinue
    }

    Context 'ConvertTo-CustomDetectionFrequency' {

        It 'Maps legacy token <Value> to <Expected>' -ForEach @(
            @{ Value = '0'; Expected = 'PT0S' }
            @{ Value = 0; Expected = 'PT0S' }
            @{ Value = '1H'; Expected = 'PT1H' }
            @{ Value = '3H'; Expected = 'PT3H' }
            @{ Value = '12H'; Expected = 'PT12H' }
            @{ Value = '24H'; Expected = 'P1D' }
            @{ Value = 'PT24H'; Expected = 'P1D' }
        ) {
            InModuleScope XDRConverter -Parameters @{ Value = $Value; Expected = $Expected } {
                ConvertTo-CustomDetectionFrequency -Value $Value | Should -Be $Expected
            }
        }

        It 'Normalises the ISO 8601 duration <Value> to <Expected>' -ForEach @(
            @{ Value = 'PT1H'; Expected = 'PT1H' }
            @{ Value = 'P1D'; Expected = 'P1D' }
            @{ Value = 'PT30M'; Expected = 'PT30M' }
            @{ Value = 'PT1440M'; Expected = 'P1D' }
            @{ Value = 'P1DT0H'; Expected = 'P1D' }
            @{ Value = 'PT0H'; Expected = 'PT0S' }
            @{ Value = 'PT90M'; Expected = 'PT1H30M' }
            @{ Value = 'PT25H'; Expected = 'P1DT1H' }
            @{ Value = 'pt90m'; Expected = 'PT1H30M' }
        ) {
            InModuleScope XDRConverter -Parameters @{ Value = $Value; Expected = $Expected } {
                ConvertTo-CustomDetectionFrequency -Value $Value | Should -Be $Expected
            }
        }

        It 'Is case-insensitive for legacy tokens' {
            InModuleScope XDRConverter {
                ConvertTo-CustomDetectionFrequency -Value '1h' | Should -Be 'PT1H'
            }
        }

        It 'Throws on an unrecognised value' {
            InModuleScope XDRConverter {
                { ConvertTo-CustomDetectionFrequency -Value '5H' } | Should -Throw "*Unsupported frequency '5H'*"
            }
        }

        It 'Rejects the malformed or unsupported duration <Value>' -ForEach @(
            @{ Value = 'P1DT' }
            @{ Value = 'P1W1D' }
            @{ Value = 'P' }
            @{ Value = 'P1W' }
            @{ Value = 'P1M' }
            @{ Value = 'P1Y' }
            @{ Value = '-PT1H' }
        ) {
            InModuleScope XDRConverter -Parameters @{ Value = $Value } {
                { ConvertTo-CustomDetectionFrequency -Value $Value } | Should -Throw "*Unsupported frequency*"
            }
        }

        It 'Keeps the legacy entity types in the schema' {
            $schema = Join-Path (Split-Path $PSScriptRoot -Parent) 'CustomDetection.schema.json'
            $json = @{ guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'; ruleName = 'r'; alertTitle = 't'; frequency = 'PT1H'; alertSeverity = 'Low'; alertDescription = 'd'; alertCategory = 'Execution'; queryText = 'q'; impactedEntities = @(@{ entityType = 'IP'; entityIdentifier = 'RemoteIP' }) } | ConvertTo-Json -Depth 5
            Test-Json -Json $json -SchemaFile $schema | Should -BeTrue
        }

        It 'Keeps the schema frequency pattern aligned with the converter' {
            $schema = Join-Path (Split-Path $PSScriptRoot -Parent) 'CustomDetection.schema.json'
            foreach ($case in @(@{ Value = 'PT1440M'; Valid = $true }, @{ Value = 'PT30M'; Valid = $true }, @{ Value = 'P1DT'; Valid = $false }, @{ Value = 'P1W'; Valid = $false }, @{ Value = 'P1M'; Valid = $false })) {
                $json = @{ guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'; ruleName = 'r'; alertTitle = 't'; frequency = $case.Value; alertSeverity = 'Low'; alertDescription = 'd'; alertCategory = 'Execution'; queryText = 'q' } | ConvertTo-Json
                (Test-Json -Json $json -SchemaFile $schema -ErrorAction SilentlyContinue) | Should -Be $case.Valid -Because $case.Value
            }
        }

        It 'Throws on an empty value' {
            InModuleScope XDRConverter {
                { ConvertTo-CustomDetectionFrequency -Value $null } | Should -Throw '*frequency is required*'
            }
        }
    }

    Context 'ConvertTo-CustomDetectionStatus' {

        It 'Defaults to enabled when nothing is given' {
            InModuleScope XDRConverter {
                ConvertTo-CustomDetectionStatus | Should -Be 'enabled'
            }
        }

        It 'Maps isEnabled true to enabled' {
            InModuleScope XDRConverter {
                ConvertTo-CustomDetectionStatus -IsEnabled $true | Should -Be 'enabled'
            }
        }

        It 'Maps isEnabled false to disabled' {
            InModuleScope XDRConverter {
                ConvertTo-CustomDetectionStatus -IsEnabled $false | Should -Be 'disabled'
            }
        }

        It 'Accepts the string true as enabled' {
            InModuleScope XDRConverter {
                ConvertTo-CustomDetectionStatus -IsEnabled 'true' | Should -Be 'enabled'
            }
        }

        It 'Lets status win over isEnabled' {
            InModuleScope XDRConverter {
                ConvertTo-CustomDetectionStatus -IsEnabled $true -Status 'disabled' -WarningAction SilentlyContinue | Should -Be 'disabled'
            }
        }

        It 'Warns when status and isEnabled contradict' {
            InModuleScope XDRConverter {
                ConvertTo-CustomDetectionStatus -IsEnabled $true -Status 'disabled' -WarningVariable w -WarningAction SilentlyContinue | Out-Null
                $w | Should -Not -BeNullOrEmpty
            }
        }

        It 'Normalises status casing' {
            InModuleScope XDRConverter {
                ConvertTo-CustomDetectionStatus -Status 'Disabled' | Should -Be 'disabled'
            }
        }

        It 'Maps autoDisabled to disabled with a warning because the API rejects it on write' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionStatus -Status 'autoDisabled' -WarningVariable w -WarningAction SilentlyContinue
                $result | Should -Be 'disabled'
                $w | Should -Not -BeNullOrEmpty
            }
        }

        It 'Returns a plain string, not a PSObject-wrapped one' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionStatus -Status 'disabled'
                ($result -is [psobject]) | Should -BeFalse
            }
        }
    }

    Context 'ConvertTo-CustomDetectionPlainObject' {

        It 'Unwraps PSObject-wrapped strings anywhere in the tree' {
            InModuleScope XDRConverter {
                $wrapped = @('b', 'a') | Sort-Object | Select-Object -First 1
                ($wrapped -is [psobject]) | Should -BeTrue
                $body = [ordered]@{
                    status = $wrapped
                    nested = @{ list = @($wrapped, 'plain'); inner = [PSCustomObject]@{ value = $wrapped } }
                }
                $plain = ConvertTo-CustomDetectionPlainObject -InputObject $body
                ($plain.status -is [psobject]) | Should -BeFalse
                $plain.status | Should -Be 'a'
                ($plain.nested.list[0] -is [psobject]) | Should -BeFalse
                ($plain.nested.inner.value -is [psobject]) | Should -BeFalse
                $plain.nested.inner.value | Should -Be 'a'
            }
        }

        It 'Keeps arrays as arrays and booleans as booleans' {
            InModuleScope XDRConverter {
                $plain = ConvertTo-CustomDetectionPlainObject -InputObject @{ flag = $true; items = @(@{ a = 1 }) }
                $plain.flag | Should -BeOfType [bool]
                $plain.items.GetType().IsArray | Should -BeTrue
                $plain.items[0].a | Should -Be 1
            }
        }
    }

    Context 'Request body serialisation' {

        It 'Serialises a built body with the Graph client JSON serializer' {
            InModuleScope XDRConverter {
                $yaml = [ordered]@{
                    guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'; ruleName = 'r'; alertTitle = 't'; alertSeverity = 'Medium'
                    alertDescription = 'd'; alertCategory = 'Execution'; mitreTechniques = @('T1059.001'); frequency = '1H'; queryText = 'q'
                    impactedEntities = @(@{ entityType = 'Machine'; entityIdentifier = 'DeviceId' })
                    actions = @(@{ actionType = 'IsolateMachine' })
                }
                $body = ConvertFrom-CustomDetectionYamlToJson -YamlObject $yaml
                $plain = ConvertTo-CustomDetectionPlainObject -InputObject $body
                $json = [Newtonsoft.Json.JsonConvert]::SerializeObject($plain)
                $json | Should -Match '"technique":"T1059"'
                $json | Should -Not -Match 'Chars'
            }
        }

        It 'Throws on an unknown status' {
            InModuleScope XDRConverter {
                { ConvertTo-CustomDetectionStatus -Status 'paused' } | Should -Throw "*Unsupported status 'paused'*"
            }
        }
    }

    Context 'ConvertTo-CustomDetectionTactics' {

        It 'Builds one tactic from the category with no techniques' {
            InModuleScope XDRConverter {
                $result = @(ConvertTo-CustomDetectionTactics -Category 'Execution')
                $result.Count | Should -Be 1
                $result[0].tactic | Should -Be 'Execution'
                $result[0].Keys | Should -Not -Contain 'techniques'
            }
        }

        It 'Groups sub-techniques under their parent technique' {
            InModuleScope XDRConverter {
                $result = @(ConvertTo-CustomDetectionTactics -Category 'Execution' -Techniques @('T1059.001', 'T1059', 'T1059.003', 'T1204'))
                $techniques = @($result[0].techniques)
                $techniques.Count | Should -Be 2
                $t1059 = $techniques | Where-Object { $_.technique -eq 'T1059' }
                @($t1059.subTechniques) | Should -Be @('T1059.001', 'T1059.003')
                $t1204 = $techniques | Where-Object { $_.technique -eq 'T1204' }
                $t1204.Keys | Should -Not -Contain 'subTechniques'
            }
        }

        It 'Creates the parent when only a sub-technique is listed' {
            InModuleScope XDRConverter {
                $result = @(ConvertTo-CustomDetectionTactics -Category 'DefenseEvasion' -Techniques @('T1562.001'))
                $result[0].techniques[0].technique | Should -Be 'T1562'
                @($result[0].techniques[0].subTechniques) | Should -Be @('T1562.001')
            }
        }

        It 'Passes non-MITRE category names through as the tactic' {
            InModuleScope XDRConverter {
                (ConvertTo-CustomDetectionTactics -Category 'SuspiciousActivity').tactic | Should -Be 'SuspiciousActivity'
            }
        }

        It 'Prefers an explicit tactics list over category and techniques' {
            InModuleScope XDRConverter {
                $explicit = @(
                    @{ tactic = 'Persistence'; techniques = @(@{ technique = 'T1547'; subTechniques = @('T1547.001') }) }
                    @{ tactic = 'Execution'; techniques = @('T1059.001') }
                )
                $result = @(ConvertTo-CustomDetectionTactics -Category 'Impact' -Techniques @('T1485') -Tactics $explicit)
                $result.Count | Should -Be 2
                $result[0].tactic | Should -Be 'Persistence'
                $result[0].techniques[0].technique | Should -Be 'T1547'
                $result[1].techniques[0].technique | Should -Be 'T1059'
                @($result[1].techniques[0].subTechniques) | Should -Be @('T1059.001')
            }
        }

        It 'Returns nothing when neither category nor tactics are given' {
            InModuleScope XDRConverter {
                ConvertTo-CustomDetectionTactics | Should -BeNullOrEmpty
            }
        }

        It 'Throws when techniques are given without a category' {
            InModuleScope XDRConverter {
                { ConvertTo-CustomDetectionTactics -Techniques @('T1059') } | Should -Throw '*category*'
            }
        }
    }

    Context 'ConvertTo-CustomDetectionEntityMappings from impactedEntities' {

        It 'Maps a device id to hosts.deviceIdColumn' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(@{ entityType = 'Machine'; entityIdentifier = 'DeviceId' })
                $result.Keys | Should -Be @('hosts')
                $result.hosts.Count | Should -Be 1
                $result.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
            }
        }

        It 'Merges device id and device name into one host item' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(
                    @{ entityType = 'Machine'; entityIdentifier = 'deviceId' }
                    @{ entityType = 'Machine'; entityIdentifier = 'DeviceName' }
                )
                $result.hosts.Count | Should -Be 1
                $result.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
                $result.hosts[0].nameColumn | Should -Be 'DeviceName'
            }
        }

        It 'Starts a second item when a column is already taken' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(
                    @{ entityType = 'Machine'; entityIdentifier = 'DeviceName' }
                    @{ entityType = 'Machine'; entityIdentifier = 'TargetDeviceName' }
                )
                $result.hosts.Count | Should -Be 2
                $result.hosts[0].nameColumn | Should -Be 'DeviceName'
                $result.hosts[1].nameColumn | Should -Be 'TargetDeviceName'
            }
        }

        It 'Maps user identifiers to the matching account column' -ForEach @(
            @{ Identifier = 'InitiatingProcessAccountUpn'; Column = 'upnColumn' }
            @{ Identifier = 'initiatingProcessAccountSid'; Column = 'sidColumn' }
            @{ Identifier = 'RecipientObjectId'; Column = 'aadUserIdColumn' }
            @{ Identifier = 'ServicePrincipalId'; Column = 'aadUserIdColumn' }
        ) {
            InModuleScope XDRConverter -Parameters @{ Identifier = $Identifier; Column = $Column } {
                $result = ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(@{ entityType = 'User'; entityIdentifier = $Identifier })
                $result.accounts[0][$Column] | Should -Be ($Identifier.Substring(0, 1).ToUpper() + $Identifier.Substring(1))
            }
        }

        It 'Drops a user mapping that carries only a name column and warns' -ForEach @(
            @{ Identifier = 'AccountName' }
            @{ Identifier = 'initiatingAccountName' }
            @{ Identifier = 'AccountDomain' }
        ) {
            InModuleScope XDRConverter -Parameters @{ Identifier = $Identifier } {
                $result = ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(
                    @{ entityType = 'Machine'; entityIdentifier = 'DeviceId' }
                    @{ entityType = 'User'; entityIdentifier = $Identifier }
                ) -WarningVariable w -WarningAction SilentlyContinue
                $result.Keys | Should -Not -Contain 'accounts'
                $result.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
                "$w" | Should -Match $Identifier
            }
        }

        It 'Keeps the name column when a sid completes the account mapping' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(
                    @{ entityType = 'User'; entityIdentifier = 'AccountName' }
                    @{ entityType = 'User'; entityIdentifier = 'AccountSid' }
                ) -WarningVariable w -WarningAction SilentlyContinue
                $result.accounts.Count | Should -Be 1
                $result.accounts[0].nameColumn | Should -Be 'AccountName'
                $result.accounts[0].sidColumn | Should -Be 'AccountSid'
                $w.Count | Should -Be 0
            }
        }

        It 'Keeps the name column when a domain completes the account mapping' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(
                    @{ entityType = 'User'; entityIdentifier = 'AccountName' }
                    @{ entityType = 'User'; entityIdentifier = 'AccountDomain' }
                )
                $result.accounts[0].nameColumn | Should -Be 'AccountName'
                $result.accounts[0].ntDomainColumn | Should -Be 'AccountDomain'
            }
        }

        It 'Accepts Account as an alias of User and Device as an alias of Machine' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(
                    @{ entityType = 'Account'; entityIdentifier = 'AccountSid' }
                    @{ entityType = 'Device'; entityIdentifier = 'DeviceId' }
                )
                $result.accounts[0].sidColumn | Should -Be 'AccountSid'
                $result.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
            }
        }

        It 'Maps a mailbox identifier to mailboxes.primaryAddressColumn' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(@{ entityType = 'Mailbox'; entityIdentifier = 'RecipientEmailAddress' })
                $result.mailboxes[0].primaryAddressColumn | Should -Be 'RecipientEmailAddress'
            }
        }

        It 'Throws on an unknown identifier without the skip switch' {
            InModuleScope XDRConverter {
                { ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(@{ entityType = 'User'; entityIdentifier = 'Bogus' }) } | Should -Throw "*Invalid identifier 'Bogus'*"
            }
        }

        It 'Warns and uses the default column for an unknown identifier with the skip switch' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(@{ entityType = 'Machine'; entityIdentifier = 'Bogus' }) -SkipIdentifierValidation -WarningVariable w -WarningAction SilentlyContinue
                $w | Should -Not -BeNullOrEmpty
                $result.hosts[0].nameColumn | Should -Be 'Bogus'
            }
        }

        It 'Throws for an unknown entity type' {
            InModuleScope XDRConverter {
                { ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(@{ entityType = 'Bogus'; entityIdentifier = 'RemoteIP' }) } | Should -Throw '*Use entityMappings*'
            }
        }

        It 'Maps legacy type <Type> with <Identifier> to <Collection>.<Column>' -ForEach @(
            @{ Type = 'IP'; Identifier = 'RemoteIP'; Collection = 'ips'; Column = 'addressColumn' }
            @{ Type = 'URL'; Identifier = 'RemoteUrl'; Collection = 'urls'; Column = 'addressColumn' }
            @{ Type = 'FileHash'; Identifier = 'SHA256'; Collection = 'files'; Column = 'sha256Column' }
            @{ Type = 'FileHash'; Identifier = 'InitiatingProcessSHA1'; Collection = 'files'; Column = 'sha1Column' }
            @{ Type = 'Process'; Identifier = 'SHA1'; Collection = 'processes'; Column = 'sha1Column' }
            @{ Type = 'RegistryKey'; Identifier = 'RegistryKey'; Collection = 'registryValues'; Column = 'keyColumn' }
            @{ Type = 'RegistryValue'; Identifier = 'RegistryValueName'; Collection = 'registryValues'; Column = 'valueNameColumn' }
        ) {
            InModuleScope XDRConverter -Parameters @{ Type = $Type; Identifier = $Identifier; Collection = $Collection; Column = $Column } {
                $result = ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(@{ entityType = $Type; entityIdentifier = $Identifier })
                $result[$Collection][0][$Column] | Should -Be $Identifier
            }
        }

        It 'Rejects a hash identifier that names neither SHA1 nor SHA256' {
            InModuleScope XDRConverter {
                { ConvertTo-CustomDetectionEntityMappings -ImpactedEntities @(@{ entityType = 'FileHash'; entityIdentifier = 'MD5' }) } | Should -Throw '*SHA1*'
            }
        }
    }

    Context 'ConvertTo-CustomDetectionEntityMappings from entityMappings' {

        It 'Accepts every documented collection with a valid column' -ForEach @(
            @{ Collection = 'accounts'; Column = 'upnColumn' }
            @{ Collection = 'amazonResources'; Column = 'amazonResourceIdColumn' }
            @{ Collection = 'azureResources'; Column = 'resourceIdColumn' }
            @{ Collection = 'cloudApplications'; Column = 'appIdColumn' }
            @{ Collection = 'dns'; Column = 'domainNameColumn' }
            @{ Collection = 'files'; Column = 'sha256Column' }
            @{ Collection = 'googleCloudResources'; Column = 'fullResourceNameColumn' }
            @{ Collection = 'hosts'; Column = 'netBiosNameColumn' }
            @{ Collection = 'ips'; Column = 'addressColumn' }
            @{ Collection = 'mailboxes'; Column = 'primaryAddressColumn' }
            @{ Collection = 'mailClusters'; Column = 'queryColumn' }
            @{ Collection = 'mailMessages'; Column = 'networkMessageIdColumn' }
            @{ Collection = 'oAuthApplications'; Column = 'oAuthAppIdColumn' }
            @{ Collection = 'processes'; Column = 'sha1Column' }
            @{ Collection = 'registryValues'; Column = 'valueNameColumn' }
            @{ Collection = 'securityGroups'; Column = 'objectIdColumn' }
            @{ Collection = 'urls'; Column = 'addressColumn' }
        ) {
            InModuleScope XDRConverter -Parameters @{ Collection = $Collection; Column = $Column } {
                $input = @{ $Collection = @(@{ $Column = 'SomeColumn' }) }
                $result = ConvertTo-CustomDetectionEntityMappings -EntityMappings $input
                $result[$Collection][0][$Column] | Should -Be 'SomeColumn'
            }
        }

        It 'Accepts a single item without array wrapping' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionEntityMappings -EntityMappings @{ hosts = @{ deviceIdColumn = 'DeviceId' } }
                $result.hosts.Count | Should -Be 1
                $result.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
            }
        }

        It 'Throws on an unknown collection' {
            InModuleScope XDRConverter {
                { ConvertTo-CustomDetectionEntityMappings -EntityMappings @{ robots = @(@{ nameColumn = 'X' }) } } | Should -Throw "*Unknown entity mapping 'robots'*"
            }
        }

        It 'Throws on an unknown column without the skip switch' {
            InModuleScope XDRConverter {
                { ConvertTo-CustomDetectionEntityMappings -EntityMappings @{ hosts = @(@{ serialColumn = 'X' }) } } | Should -Throw "*Invalid column 'serialColumn'*"
            }
        }

        It 'Warns on an unknown column with the skip switch' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionEntityMappings -EntityMappings @{ hosts = @(@{ serialColumn = 'X' }) } -SkipIdentifierValidation -WarningVariable w -WarningAction SilentlyContinue
                $w | Should -Not -BeNullOrEmpty
                $result.hosts[0].serialColumn | Should -Be 'X'
            }
        }

        It 'Drops empty columns and empty collections' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionEntityMappings -EntityMappings @{
                    hosts    = @(@{ deviceIdColumn = 'DeviceId'; nameColumn = '' })
                    accounts = @()
                    files    = $null
                }
                $result.Keys | Should -Be @('hosts')
                $result.hosts[0].Keys | Should -Be @('deviceIdColumn')
            }
        }
    }

    Context 'ConvertTo-CustomDetectionEntityMappings input hygiene' {

        It 'Ignores OData annotations on explicit mapping items' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionEntityMappings -EntityMappings @{ hosts = @(@{ '@odata.type' = '#microsoft.graph.security.hostEntityMapping'; deviceIdColumn = 'DeviceId' }) }
                @($result.hosts[0].Keys) | Should -Be @('deviceIdColumn')
            }
        }

        It 'Rejects an explicit account mapping without a key column' {
            InModuleScope XDRConverter {
                { ConvertTo-CustomDetectionEntityMappings -EntityMappings @{ accounts = @(@{ nameColumn = 'AccountName' }) } } | Should -Throw '*aadUserIdColumn*'
            }
        }

        It 'Drops an incomplete explicit account mapping with a warning when validation is skipped' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionEntityMappings -EntityMappings @{ accounts = @(@{ nameColumn = 'AccountName' }); hosts = @(@{ deviceIdColumn = 'DeviceId' }) } -SkipIdentifierValidation -WarningVariable w -WarningAction SilentlyContinue
                $result.Keys | Should -Not -Contain 'accounts'
                "$w" | Should -Match 'AccountName'
            }
        }
    }

    Context 'Rule identity' {

        It 'Get-CustomDetectionIdentity reads the guid out of a rule-prefixed id' {
            InModuleScope XDRConverter {
                $rule = [PSCustomObject]@{ id = 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'; detectionAction = [PSCustomObject]@{ alertTemplate = [PSCustomObject]@{ description = 'no tag here' } } }
                Get-CustomDetectionIdentity -Rule $rule | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
            }
        }

        It 'Get-CustomDetectionIdByDetectorId matches a rule-prefixed id' {
            InModuleScope XDRConverter {
                Mock Assert-MgGraphConnection {}
                $script:DetectionIdsCache = @{
                    Data      = @([PSCustomObject]@{ Id = 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'; DetectorId = 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'; DisplayName = 'R'; DescriptionTag = $null; TagPrefix = $null })
                    ExpiresAt = [datetime]::UtcNow.AddHours(1)
                }
                Get-CustomDetectionIdByDetectorId -DetectorId '81fb771a-c57e-41b8-9905-63dbf267c13f' | Should -Be 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f'
                $script:DetectionIdsCache = @{ Data = $null; ExpiresAt = [datetime]::MinValue }
            }
        }
    }

    Context 'ConvertTo-CustomDetectionLegacyYaml' {

        It 'Drops a column the legacy identifiers cannot express and warns' {
            InModuleScope XDRConverter {
                $yaml = @{
                    guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'; ruleName = 'R'; alertTitle = 'T'; alertSeverity = 'Low'; alertDescription = 'D'; frequency = 'PT1H'; queryText = 'Q'
                    tactics = @(@{ tactic = 'Execution' })
                    entityMappings = @{ hosts = @(@{ deviceIdColumn = 'HostId' }, @{ deviceIdColumn = 'DeviceId' }) }
                }
                $legacy = ConvertTo-CustomDetectionLegacyYaml -YamlObject $yaml -WarningVariable w -WarningAction SilentlyContinue
                @($legacy.impactedEntities).Count | Should -Be 1
                $legacy.impactedEntities[0].entityIdentifier | Should -Be 'deviceId'
                "$w" | Should -Match 'HostId'
            }
        }

        It 'Emits the legacy entity types for ip, url, file, process and registry mappings' {
            InModuleScope XDRConverter {
                $yaml = @{
                    guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'; ruleName = 'R'; alertTitle = 'T'; alertSeverity = 'Low'; alertDescription = 'D'; frequency = 'PT1H'; queryText = 'Q'
                    tactics = @(@{ tactic = 'Execution' })
                    entityMappings = @{
                        ips            = @(@{ addressColumn = 'RemoteIP' })
                        urls           = @(@{ addressColumn = 'RemoteUrl' })
                        files          = @(@{ sha256Column = 'SHA256'; nameColumn = 'FileName' })
                        processes      = @(@{ sha1Column = 'InitiatingProcessSHA1' })
                        registryValues = @(@{ keyColumn = 'RegistryKey'; valueNameColumn = 'RegistryValueName' })
                    }
                }
                $legacy = ConvertTo-CustomDetectionLegacyYaml -YamlObject $yaml -WarningVariable w -WarningAction SilentlyContinue
                $pairs = @($legacy.impactedEntities | ForEach-Object { "$($_.entityType)=$($_.entityIdentifier)" })
                $pairs | Should -Contain 'IP=remoteIP'
                $pairs | Should -Contain 'URL=remoteUrl'
                $pairs | Should -Contain 'FileHash=sHA256'
                $pairs | Should -Contain 'Process=initiatingProcessSHA1'
                $pairs | Should -Contain 'RegistryKey=registryKey'
                $pairs | Should -Contain 'RegistryValue=registryValueName'
                $pairs.Count | Should -Be 6
                "$w" | Should -Match 'FileName'
            }
        }

        It 'Warns when an action column mapping is lost' {
            InModuleScope XDRConverter {
                $yaml = @{
                    guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'; ruleName = 'R'; alertTitle = 'T'; alertSeverity = 'Low'; alertDescription = 'D'; frequency = 'PT1H'; queryText = 'Q'
                    tactics = @(@{ tactic = 'Execution' })
                    actions = @(
                        @{ actionType = 'IsolateMachine'; additionalFields = @{ deviceIdColumn = 'TargetDeviceId'; isolationType = 'Selective' } }
                        @{ actionType = 'RunAntivirusScan'; additionalFields = @{ deviceIdColumn = 'DeviceId' } }
                    )
                }
                $legacy = ConvertTo-CustomDetectionLegacyYaml -YamlObject $yaml -WarningVariable w -WarningAction SilentlyContinue
                @($legacy.actions).Count | Should -Be 2
                $w.Count | Should -Be 1
                "$w" | Should -Match 'TargetDeviceId'
            }
        }
    }

    Context 'ConvertFrom-CustomDetectionEntityMappings' {

        It 'Strips null collections and empty columns from a Graph response' {
            InModuleScope XDRConverter {
                $graph = [PSCustomObject]@{
                    accounts = @([PSCustomObject]@{ aadUserIdColumn = ''; nameColumn = ''; sidColumn = 'InitiatingProcessAccountSid'; upnColumn = '' })
                    hosts    = @([PSCustomObject]@{ deviceIdColumn = ''; nameColumn = 'DeviceName' })
                    files    = $null
                    ips      = @()
                }
                $result = ConvertFrom-CustomDetectionEntityMappings -EntityMappings $graph
                @($result.Keys) | Should -Be @('accounts', 'hosts')
                @($result.accounts[0].Keys) | Should -Be @('sidColumn')
                $result.hosts[0].nameColumn | Should -Be 'DeviceName'
            }
        }

        It 'Wraps a single object item into a list' {
            InModuleScope XDRConverter {
                $graph = [PSCustomObject]@{ hosts = [PSCustomObject]@{ deviceIdColumn = 'DeviceId' } }
                $result = ConvertFrom-CustomDetectionEntityMappings -EntityMappings $graph
                $result.hosts.Count | Should -Be 1
                $result.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
            }
        }

        It 'Translates legacy impactedAssets' {
            InModuleScope XDRConverter {
                $assets = @(
                    [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.security.impactedDeviceAsset'; identifier = 'deviceId' }
                    [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.security.impactedUserAsset'; identifier = 'initiatingProcessAccountUpn' }
                    [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.security.impactedMailboxAsset'; identifier = 'recipientEmailAddress' }
                )
                $result = ConvertFrom-CustomDetectionEntityMappings -ImpactedAssets $assets
                $result.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
                $result.accounts[0].upnColumn | Should -Be 'InitiatingProcessAccountUpn'
                $result.mailboxes[0].primaryAddressColumn | Should -Be 'RecipientEmailAddress'
            }
        }

        It 'Returns nothing for an empty input' {
            InModuleScope XDRConverter {
                ConvertFrom-CustomDetectionEntityMappings -EntityMappings $null | Should -BeNullOrEmpty
            }
        }
    }

    Context 'ConvertTo-CustomDetectionAutomatedActions' {

        It 'Maps <ActionType> to <Collection> with default columns' -ForEach @(
            @{ ActionType = 'IsolateMachine'; Collection = 'isolateDevices'; Expected = @{ deviceIdColumn = 'DeviceId'; isolationType = 'full' } }
            @{ ActionType = 'CollectInvestigationPackage'; Collection = 'collectInvestigationPackages'; Expected = @{ deviceIdColumn = 'DeviceId' } }
            @{ ActionType = 'RunAntivirusScan'; Collection = 'runAntivirusScans'; Expected = @{ deviceIdColumn = 'DeviceId' } }
            @{ ActionType = 'InitiateInvestigation'; Collection = 'initiateInvestigations'; Expected = @{ deviceIdColumn = 'DeviceId' } }
            @{ ActionType = 'RestrictAppExecution'; Collection = 'restrictAppExecutions'; Expected = @{ deviceIdColumn = 'DeviceId' } }
            @{ ActionType = 'StopAndQuarantineFile'; Collection = 'stopAndQuarantineFiles'; Expected = @{ deviceIdColumn = 'DeviceId'; sha1Column = 'SHA1' } }
            @{ ActionType = 'AllowFile'; Collection = 'allowFiles'; Expected = @{ sha1Column = 'SHA1' } }
            @{ ActionType = 'BlockFile'; Collection = 'blockFiles'; Expected = @{ sha1Column = 'SHA1' } }
            @{ ActionType = 'DisableUser'; Collection = 'disableUsers'; Expected = @{ accountSidColumn = 'AccountSid' } }
            @{ ActionType = 'ForceUserPasswordReset'; Collection = 'forceUserPasswordResets'; Expected = @{ accountSidColumn = 'AccountSid' } }
            @{ ActionType = 'MarkUserAsCompromised'; Collection = 'markUsersAsCompromised'; Expected = @{ accountObjectIdColumn = 'AccountObjectId' } }
            @{ ActionType = 'HardDeleteEmail'; Collection = 'hardDeleteEmails'; Expected = @{ networkMessageIdColumn = 'NetworkMessageId'; recipientColumn = 'RecipientEmailAddress' } }
            @{ ActionType = 'SoftDeleteEmail'; Collection = 'softDeleteEmails'; Expected = @{ networkMessageIdColumn = 'NetworkMessageId'; recipientColumn = 'RecipientEmailAddress' } }
            @{ ActionType = 'MoveEmailToInbox'; Collection = 'moveEmailsToInbox'; Expected = @{ networkMessageIdColumn = 'NetworkMessageId'; recipientColumn = 'RecipientEmailAddress' } }
            @{ ActionType = 'MoveEmailToJunk'; Collection = 'moveEmailsToJunk'; Expected = @{ networkMessageIdColumn = 'NetworkMessageId'; recipientColumn = 'RecipientEmailAddress' } }
            @{ ActionType = 'MoveEmailToDeletedItems'; Collection = 'moveEmailsToDeletedItems'; Expected = @{ networkMessageIdColumn = 'NetworkMessageId'; recipientColumn = 'RecipientEmailAddress' } }
        ) {
            InModuleScope XDRConverter -Parameters @{ ActionType = $ActionType; Collection = $Collection; Expected = $Expected } {
                $result = ConvertTo-CustomDetectionAutomatedActions -Actions @(@{ actionType = $ActionType })
                @($result.Keys) | Should -Be @($Collection)
                $item = $result[$Collection][0]
                @($item.Keys | Sort-Object) | Should -Be @($Expected.Keys | Sort-Object)
                foreach ($k in $Expected.Keys) { $item[$k] | Should -Be $Expected[$k] }
            }
        }

        It 'Lets additionalFields override the default columns' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionAutomatedActions -Actions @(
                    @{ actionType = 'BlockFile'; additionalFields = @{ sha256Column = 'InitiatingProcessSHA256'; deviceGroupNames = @('Servers') } }
                )
                $result.blockFiles[0].sha256Column | Should -Be 'InitiatingProcessSHA256'
                $result.blockFiles[0].Keys | Should -Not -Contain 'sha1Column'
                @($result.blockFiles[0].deviceGroupNames) | Should -Be @('Servers')
            }
        }

        It 'Lowercases a valid isolationType and defaults an invalid one to full' {
            InModuleScope XDRConverter {
                $selective = ConvertTo-CustomDetectionAutomatedActions -Actions @(@{ actionType = 'IsolateMachine'; additionalFields = @{ isolationType = 'Selective' } })
                $selective.isolateDevices[0].isolationType | Should -Be 'selective'

                $bad = ConvertTo-CustomDetectionAutomatedActions -Actions @(@{ actionType = 'IsolateMachine'; additionalFields = @{ isolationType = 'Partial' } }) -WarningAction SilentlyContinue
                $bad.isolateDevices[0].isolationType | Should -Be 'full'
            }
        }

        It 'Adds a second item when the same action type is listed twice' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionAutomatedActions -Actions @(
                    @{ actionType = 'DisableUser' }
                    @{ actionType = 'DisableUser'; additionalFields = @{ accountSidColumn = 'InitiatingProcessAccountSid' } }
                )
                $result.disableUsers.Count | Should -Be 2
                $result.disableUsers[1].accountSidColumn | Should -Be 'InitiatingProcessAccountSid'
            }
        }

        It 'Is case-insensitive on the action type' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionAutomatedActions -Actions @(@{ actionType = 'isolatemachine' })
                @($result.Keys) | Should -Be @('isolateDevices')
            }
        }

        It 'Throws on an unsupported action type' {
            InModuleScope XDRConverter {
                { ConvertTo-CustomDetectionAutomatedActions -Actions @(@{ actionType = 'UnsupportedAction' }) } | Should -Throw "*Unsupported response action type 'UnsupportedAction'*"
            }
        }

        It 'Translates legacy responseActions' {
            InModuleScope XDRConverter {
                $legacy = @(
                    [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'; identifier = 'deviceId'; isolationType = 'selective' }
                    [PSCustomObject]@{ '@odata.type' = '#microsoft.graph.security.restrictAppExecutionResponseAction'; identifier = 'deviceId' }
                )
                $result = ConvertTo-CustomDetectionAutomatedActions -ResponseActions $legacy
                $result.isolateDevices[0].isolationType | Should -Be 'selective'
                $result.restrictAppExecutions[0].deviceIdColumn | Should -Be 'DeviceId'
            }
        }

        It 'Returns nothing for an empty input' {
            InModuleScope XDRConverter {
                ConvertTo-CustomDetectionAutomatedActions -Actions @() | Should -BeNullOrEmpty
            }
        }
    }

    Context 'Complete-CustomDetectionPatchBody' {

        It 'Fills every action and entity collection so omitted ones are cleared on PATCH' {
            InModuleScope XDRConverter {
                $body = [ordered]@{
                    id              = 'x'
                    displayName     = 'r'
                    status          = 'enabled'
                    queryCondition  = [ordered]@{ queryText = 'q' }
                    schedule        = [ordered]@{ frequency = 'PT1H' }
                    detectionAction = [ordered]@{
                        alertTemplate    = [ordered]@{
                            title = 't'; description = 'd'; severity = 'low'
                            tactics = @([ordered]@{ tactic = 'Execution' })
                            entityMappings = [ordered]@{ hosts = @([ordered]@{ deviceIdColumn = 'DeviceId' }) }
                        }
                        automatedActions = [ordered]@{ isolateDevices = @([ordered]@{ deviceIdColumn = 'DeviceId'; isolationType = 'full' }) }
                    }
                }
                $patch = Complete-CustomDetectionPatchBody -Body $body

                $patch.Keys | Should -Not -Contain 'id'
                @($patch.detectionAction.automatedActions.Keys).Count | Should -Be 16
                $patch.detectionAction.automatedActions.isolateDevices[0].deviceIdColumn | Should -Be 'DeviceId'
                $patch.detectionAction.automatedActions.blockFiles.GetType().IsArray | Should -BeTrue
                @($patch.detectionAction.automatedActions.blockFiles).Count | Should -Be 0
                @($patch.detectionAction.alertTemplate.entityMappings.Keys).Count | Should -Be 17
                @($patch.detectionAction.alertTemplate.entityMappings.accounts).Count | Should -Be 0
                $patch.detectionAction.alertTemplate.entityMappings.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
                @($patch.detectionAction.organizationalScope.deviceGroups).Count | Should -Be 0
                $patch.detectionAction.alertTemplate.Keys | Should -Not -Contain 'customDetails'
            }
        }

        It 'Keeps populated scope and custom details' {
            InModuleScope XDRConverter {
                $body = [ordered]@{
                    id = 'x'; displayName = 'r'; status = 'enabled'
                    queryCondition = [ordered]@{ queryText = 'q' }; schedule = [ordered]@{ frequency = 'PT1H' }
                    detectionAction = [ordered]@{
                        alertTemplate = [ordered]@{ title = 't'; description = 'd'; severity = 'low'; tactics = @([ordered]@{ tactic = 'Execution' }); customDetails = [ordered]@{ A = 'B' } }
                        organizationalScope = [ordered]@{ deviceGroups = @('Servers') }
                    }
                }
                $patch = Complete-CustomDetectionPatchBody -Body $body
                @($patch.detectionAction.organizationalScope.deviceGroups) | Should -Be @('Servers')
                $patch.detectionAction.alertTemplate.customDetails.A | Should -Be 'B'
                $body.detectionAction.Keys | Should -Not -Contain 'automatedActions'
            }
        }
    }

    Context 'ConvertTo-CustomDetectionAutomatedActions hash columns' {

        It 'Rejects a file action that names both hash columns' {
            InModuleScope XDRConverter {
                { ConvertTo-CustomDetectionAutomatedActions -Actions @(@{ actionType = 'BlockFile'; additionalFields = @{ sha1Column = 'SHA1'; sha256Column = 'SHA256' } }) } | Should -Throw '*one hash column*'
            }
        }
    }

    Context 'ConvertTo-CustomDetectionAutomatedActions documented fields' {

        It 'Rejects a field the action type does not document' -ForEach @(
            @{ ActionType = 'IsolateMachine'; Field = 'recipientColumn' }
            @{ ActionType = 'StopAndQuarantineFile'; Field = 'sha256Column' }
            @{ ActionType = 'DisableUser'; Field = 'deviceIdColumn' }
            @{ ActionType = 'RunAntivirusScan'; Field = 'isolationType' }
        ) {
            InModuleScope XDRConverter -Parameters @{ ActionType = $ActionType; Field = $Field } {
                { ConvertTo-CustomDetectionAutomatedActions -Actions @(@{ actionType = $ActionType; additionalFields = @{ $Field = 'X' } }) } | Should -Throw "*$Field*"
            }
        }

        It 'Accepts every documented field of a file action' {
            InModuleScope XDRConverter {
                $result = ConvertTo-CustomDetectionAutomatedActions -Actions @(@{ actionType = 'AllowFile'; additionalFields = @{ sha256Column = 'SHA256'; deviceGroupNames = @('Servers') } })
                $result.allowFiles[0].sha256Column | Should -Be 'SHA256'
                @($result.allowFiles[0].deviceGroupNames) | Should -Be @('Servers')
            }
        }
    }

    Context 'ConvertFrom-CustomDetectionAutomatedActions OData annotations' {

        It 'Ignores OData annotations on the collection and its items' {
            InModuleScope XDRConverter {
                $graph = [PSCustomObject]@{
                    '@odata.type'  = '#microsoft.graph.security.automatedActions'
                    isolateDevices = @([PSCustomObject]@{ '@odata.type' = '#microsoft.graph.security.isolateDeviceAction'; deviceIdColumn = 'DeviceId'; isolationType = 'full' })
                }
                $result = @(ConvertFrom-CustomDetectionAutomatedActions -AutomatedActions $graph -WarningVariable w -WarningAction SilentlyContinue)
                $result.Count | Should -Be 1
                $result[0].additionalFields.Keys | Should -Not -Contain '@odata.type'
                $w.Count | Should -Be 0
            }
        }
    }

    Context 'ConvertFrom-CustomDetectionAutomatedActions' {

        It 'Turns populated collections into YAML actions and skips null ones' {
            InModuleScope XDRConverter {
                $graph = [PSCustomObject]@{
                    allowFiles     = $null
                    isolateDevices = @([PSCustomObject]@{ deviceIdColumn = 'DeviceId'; isolationType = 'full' })
                    disableUsers   = @([PSCustomObject]@{ accountSidColumn = 'AccountSid' })
                }
                $result = @(ConvertFrom-CustomDetectionAutomatedActions -AutomatedActions $graph)
                $result.Count | Should -Be 2
                $isolate = $result | Where-Object { $_.actionType -eq 'IsolateMachine' }
                $isolate.additionalFields.isolationType | Should -Be 'Full'
                $isolate.additionalFields.deviceIdColumn | Should -Be 'DeviceId'
                $disable = $result | Where-Object { $_.actionType -eq 'DisableUser' }
                $disable.additionalFields.accountSidColumn | Should -Be 'AccountSid'
            }
        }

        It 'Wraps a single object item into a list' {
            InModuleScope XDRConverter {
                $graph = [PSCustomObject]@{ runAntivirusScans = [PSCustomObject]@{ deviceIdColumn = 'DeviceId' } }
                $result = @(ConvertFrom-CustomDetectionAutomatedActions -AutomatedActions $graph)
                $result.Count | Should -Be 1
                $result[0].actionType | Should -Be 'RunAntivirusScan'
            }
        }

        It 'Keeps unknown collections with a warning instead of dropping them' {
            InModuleScope XDRConverter {
                $graph = [PSCustomObject]@{ rebootDevices = @([PSCustomObject]@{ deviceIdColumn = 'DeviceId' }) }
                $result = @(ConvertFrom-CustomDetectionAutomatedActions -AutomatedActions $graph -WarningVariable w -WarningAction SilentlyContinue)
                $w | Should -Not -BeNullOrEmpty
                $result[0].actionType | Should -Be 'rebootDevices'
                $result[0].additionalFields.deviceIdColumn | Should -Be 'DeviceId'
            }
        }

        It 'Translates legacy responseActions' {
            InModuleScope XDRConverter {
                $legacy = @([PSCustomObject]@{ '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'; identifier = 'deviceId'; isolationType = 'selective' })
                $result = @(ConvertFrom-CustomDetectionAutomatedActions -ResponseActions $legacy)
                $result[0].actionType | Should -Be 'IsolateMachine'
                $result[0].additionalFields.isolationType | Should -Be 'Selective'
            }
        }
    }
}
