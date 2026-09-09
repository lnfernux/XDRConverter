Describe 'Deploy-CustomDetection' {

    BeforeAll {
        # Create a stub for Invoke-MgGraphRequest so Pester can mock it
        # even when Microsoft.Graph.Authentication is not installed.
        # The stub must declare the parameters used by Invoke-MgGraphRequestWithRetry
        # so that Pester's generated mock exposes them (e.g. $Body for assertions).
        if (-not (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
            function global:Invoke-MgGraphRequest {
                param($Method, $Uri, $Body, $Headers, $OutputType)
            }
        }

        $ModulePath = Split-Path -Path $PSScriptRoot -Parent
        $ModulePath = Join-Path -Path $ModulePath -ChildPath 'src' | Join-Path -ChildPath 'XDRConverter.psd1'
        Import-Module -Name $ModulePath -Force
    }

    AfterAll {
        Remove-Module -Name XDRConverter -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        # Mock all Graph-dependent functions at the Describe level so every test
        # runs without real authentication. Individual contexts/tests can override
        # these mocks with more specific behaviour as needed.
        Mock Assert-MgGraphConnection {} -ModuleName XDRConverter
        Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter
        Mock Get-CustomDetectionIdByDetectorId { return $null } -ModuleName XDRConverter
        Mock Get-CustomDetection { return @() } -ModuleName XDRConverter
    }

    Context 'Parameter Validation' {

        It 'Should throw when InputFile does not exist' {
            { Deploy-CustomDetection -InputFile 'C:\nonexistent\file.yaml' } | Should -Throw
        }

        It 'Should have Mandatory InputFile parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $param = $cmd.Parameters['InputFile']
            $mandatory = $param.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' } |
            Select-Object -First 1
            $mandatory.Mandatory | Should -Be $true
        }

        It 'Should accept valid Severity values' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $severityParam = $cmd.Parameters['Severity']
            $validateSet = $severityParam.Attributes | Where-Object { $_.TypeId.Name -eq 'ValidateSetAttribute' }
            $validateSet.ValidValues | Should -Contain 'Informational'
            $validateSet.ValidValues | Should -Contain 'Low'
            $validateSet.ValidValues | Should -Contain 'Medium'
            $validateSet.ValidValues | Should -Contain 'High'
        }

        It 'Should have SupportsShouldProcess' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $cmdletBinding = $cmd.ScriptBlock.Attributes | Where-Object { $_.TypeId.Name -eq 'CmdletBindingAttribute' }
            $cmdletBinding.SupportsShouldProcess | Should -Be $true
        }

        It 'Should have TitlePrefix parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $cmd.Parameters.Keys | Should -Contain 'TitlePrefix'
        }

        It 'Should have Disabled switch parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $param = $cmd.Parameters['Disabled']
            $param.ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It 'Should have NoDescriptionTag switch parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $param = $cmd.Parameters['NoDescriptionTag']
            $param.ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It 'Should have DescriptionTagPrefix parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $cmd.Parameters.Keys | Should -Contain 'DescriptionTagPrefix'
        }

        It 'Should have Force switch parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $param = $cmd.Parameters['Force']
            $param.ParameterType.Name | Should -Be 'SwitchParameter'
        }
    }

    Context 'File Loading' {

        It 'Should reject unsupported file extensions' {
            $tempFile = Join-Path TestDrive: 'unsupported.txt'
            'test' | Out-File -FilePath $tempFile -Encoding UTF8

            { Deploy-CustomDetection -InputFile $tempFile } | Should -Throw '*Unsupported file extension*'
        }

        It 'Should load YAML files successfully' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-Deploy
isEnabled: true
alertTitle: Test Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test description
alertCategory: DefenseEvasion
queryText: DeviceEvents | where ActionType == "Test"
"@
            $tempFile = Join-Path TestDrive: 'load-yaml.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Mock Invoke-MgGraphRequest { return @{ id = 'new-rule-id' } } -ModuleName XDRConverter

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result | Should -Not -BeNullOrEmpty
            $result.Action | Should -Be 'Created'
            $result.DetectorId | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
        }

        It 'Should load JSON files successfully' {
            $testJson = @"
{
    "detectorId": "81fb771a-c57e-41b8-9905-63dbf267c13f",
    "displayName": "TEST-Deploy",
    "isEnabled": true,
    "detectionAction": {
        "alertTemplate": {
            "title": "Test Alert",
            "description": "Test description",
            "severity": "medium",
            "category": "DefenseEvasion"
        },
        "organizationalScope": null,
        "responseActions": []
    },
    "queryCondition": { "queryText": "DeviceEvents" },
    "schedule": { "period": "0" }
}
"@
            $tempFile = Join-Path TestDrive: 'load-json.json'
            $testJson | Out-File -FilePath $tempFile -Encoding UTF8

            Mock Invoke-MgGraphRequest { return @{ id = 'new-rule-id' } } -ModuleName XDRConverter

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result | Should -Not -BeNullOrEmpty
            $result.Action | Should -Be 'Created'
        }
    }

    Context 'Description Tag' {

        BeforeEach {
            Mock Invoke-MgGraphRequest {
                # Capture the body for assertions
                $script:CapturedBody = $Body
                return @{ id = 'new-rule-id' }
            } -ModuleName XDRConverter
        }

        It 'Should append [<UUID>] tag to description by default' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: Original desc
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'tag-default.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $script:CapturedBody.detectionAction.alertTemplate.description |
            Should -Match '\[81fb771a-c57e-41b8-9905-63dbf267c13f\]$'
        }

        It 'Should append [PREFIX:<UUID>] tag when DescriptionTagPrefix is given' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: Original desc
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'tag-prefix.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -DescriptionTagPrefix 'PREFIX' -Confirm:$false
            $script:CapturedBody.detectionAction.alertTemplate.description |
            Should -Match '\[PREFIX:81fb771a-c57e-41b8-9905-63dbf267c13f\]$'
        }

        It 'Should NOT append tag when -NoDescriptionTag is set' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: Original desc
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'tag-none.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -NoDescriptionTag -Confirm:$false
            $script:CapturedBody.detectionAction.alertTemplate.description |
            Should -Be 'Original desc'
        }

        It 'Should not duplicate the tag on repeated deploys' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: Original desc [81fb771a-c57e-41b8-9905-63dbf267c13f]
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'tag-nodupe.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $desc = $script:CapturedBody.detectionAction.alertTemplate.description
            # Should contain the tag exactly once
            $UUIDmatches = [regex]::Matches($desc, [regex]::Escape('81fb771a-c57e-41b8-9905-63dbf267c13f'))
            $UUIDmatches.Count | Should -Be 1
        }
    }

    Context 'Overrides' {

        BeforeEach {
            Mock Invoke-MgGraphRequest {
                $script:CapturedBody = $Body
                return @{ id = 'new-rule-id' }
            } -ModuleName XDRConverter
        }

        It 'Should override severity when -Severity is specified' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Low
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'override-severity.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Severity High -Confirm:$false
            $script:CapturedBody.detectionAction.alertTemplate.severity | Should -Be 'high'
        }

        It 'Should prepend TitlePrefix to displayName and alertTitle' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: MyRule
isEnabled: true
alertTitle: My Alert
frequency: 0
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'override-titleprefix.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -TitlePrefix '[PREFIX] ' -Confirm:$false
            $script:CapturedBody.displayName | Should -Be '[PREFIX] MyRule'
            $script:CapturedBody.detectionAction.alertTemplate.title | Should -Be '[PREFIX] My Alert'
        }

        It 'Should not double-prefix if title already starts with prefix' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: "[PREFIX] MyRule"
isEnabled: true
alertTitle: "[PREFIX] My Alert"
frequency: 0
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'override-nodoubleprefix.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -TitlePrefix '[PREFIX] ' -Confirm:$false
            $script:CapturedBody.displayName | Should -Be '[PREFIX] MyRule'
        }

        It 'Should deploy in disabled mode with -Disabled switch' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'override-disabled.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Disabled -Confirm:$false
            $script:CapturedBody.status | Should -Be 'disabled'
            $script:CapturedBody.Keys | Should -Not -Contain 'isEnabled'
        }
    }

    Context 'Request body shape' {

        BeforeEach {
            Mock Invoke-MgGraphRequest {
                $script:CapturedBody = $Body
                $script:CapturedMethod = $Method
                return @{ id = 'new-rule-id' }
            } -ModuleName XDRConverter
            InModuleScope XDRConverter {
                $script:DetectionIdsCache = @{ Data = @([PSCustomObject]@{ Id = 'stale' }); ExpiresAt = [datetime]::UtcNow.AddHours(1) }
            }
        }

        It 'Should POST without an id and with the current property names' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: BODY-Create
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
mitreTechniques:
  - T1562.001
impactedEntities:
  - entityType: Machine
    entityIdentifier: DeviceId
actions:
  - actionType: IsolateMachine
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-create.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Created'
            $result.DetectorId | Should -Be '81fb771a-c57e-41b8-9905-63dbf267c13f'
            $script:CapturedMethod | Should -Be 'POST'

            $body = $script:CapturedBody
            $body.Keys | Should -Not -Contain 'id'
            $body.status | Should -Be 'enabled'
            $body.schedule.frequency | Should -Be 'PT1H'
            $body.detectionAction.alertTemplate.tactics[0].tactic | Should -Be 'DefenseEvasion'
            $body.detectionAction.alertTemplate.entityMappings.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
            $body.detectionAction.automatedActions.isolateDevices[0].isolationType | Should -Be 'full'
            $body.Keys | Should -Not -Contain 'detectorId'
            $body.Keys | Should -Not -Contain 'isEnabled'
            $body.schedule.Keys | Should -Not -Contain 'period'
            $body.detectionAction.Keys | Should -Not -Contain 'responseActions'
        }

        It 'Should hand the Graph client a body without PSObject-wrapped values' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: BODY-Plain
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
mitreTechniques:
  - T1562.001
impactedEntities:
  - entityType: Machine
    entityIdentifier: DeviceId
actions:
  - actionType: IsolateMachine
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-plain.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Confirm:$false | Out-Null

            function Find-WrappedValue {
                param($Value, [string]$Path)
                if ($null -eq $Value) { return }
                if ($Value -is [string] -or $Value -is [ValueType]) {
                    if ($Value -is [psobject]) { return $Path }
                    return
                }
                if ($Value -is [System.Collections.IDictionary]) {
                    foreach ($k in $Value.Keys) { Find-WrappedValue -Value $Value[$k] -Path "$Path.$k" }
                    return
                }
                if ($Value -is [System.Collections.IEnumerable]) {
                    $i = 0
                    foreach ($item in $Value) { Find-WrappedValue -Value $item -Path "$Path[$i]"; $i++ }
                    return
                }
                foreach ($p in $Value.PSObject.Properties) { Find-WrappedValue -Value $p.Value -Path "$Path.$($p.Name)" }
            }
            $wrapped = @(Find-WrappedValue -Value $script:CapturedBody -Path 'body')
            $wrapped | Should -BeNullOrEmpty
        }

        It 'Should clear the id cache after a create' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: BODY-Cache
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-cache.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Confirm:$false | Out-Null
            InModuleScope XDRConverter {
                $script:DetectionIdsCache.Data | Should -BeNullOrEmpty
            }
        }

        It 'Should find an untagged rule by display name when -NoDescriptionTag is set' {
            InModuleScope XDRConverter {
                $script:DetectionIdsCache = @{
                    Data      = @([PSCustomObject]@{ Id = '77'; DetectorId = '77'; DisplayName = 'BODY-NoTag'; DescriptionTag = $null; TagPrefix = $null })
                    ExpiresAt = [datetime]::UtcNow.AddHours(1)
                }
            }
            Mock Get-CustomDetection {
                return @{
                    id              = '77'
                    displayName     = 'BODY-NoTag'
                    status          = 'enabled'
                    detectionAction = @{ alertTemplate = @{ title = 'Old'; description = 'Old'; severity = 'low'; tactics = @(@{ tactic = 'DefenseEvasion' }) } }
                    queryCondition  = @{ queryText = 'DeviceEvents' }
                    schedule        = @{ frequency = 'PT1H' }
                }
            } -ModuleName XDRConverter

            $testYaml = @"
guid: 4d3a1c81-d784-4ef2-9e17-18d2d8e455f6
ruleName: BODY-NoTag
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-notag.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -NoDescriptionTag -Confirm:$false
            $result.Action | Should -Be 'Updated'
            $result.RuleId | Should -Be '77'
            $script:CapturedMethod | Should -Be 'PATCH'
        }

        It 'Should PATCH without the id property' {
            $guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            Mock Get-CustomDetectionIdByDetectorId { return '48' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{
                    id              = '48'
                    displayName     = 'OLD'
                    status          = 'enabled'
                    detectionAction = @{ alertTemplate = @{ title = 'Old'; description = "Old [$guid]"; severity = 'low'; tactics = @(@{ tactic = 'DefenseEvasion' }) } }
                    queryCondition  = @{ queryText = 'DeviceEvents' }
                    schedule        = @{ frequency = 'PT1H' }
                }
            } -ModuleName XDRConverter

            $testYaml = @"
guid: $guid
ruleName: BODY-Patch
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-patch.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Updated'
            $result.RuleId | Should -Be '48'
            $script:CapturedMethod | Should -Be 'PATCH'
            $script:CapturedBody.Keys | Should -Not -Contain 'id'
            $script:CapturedBody.displayName | Should -Be 'BODY-Patch'

            # Every collection is present on PATCH so a removed action or entity is cleared server-side
            @($script:CapturedBody.detectionAction.automatedActions.Keys).Count | Should -Be 16
            @($script:CapturedBody.detectionAction.automatedActions.isolateDevices).Count | Should -Be 0
            @($script:CapturedBody.detectionAction.alertTemplate.entityMappings.Keys).Count | Should -Be 17
            @($script:CapturedBody.detectionAction.organizationalScope.deviceGroups).Count | Should -Be 0
        }

        It 'Should POST only the populated collections' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: BODY-Post-Sparse
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-post-sparse.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            Deploy-CustomDetection -InputFile $tempFile -Confirm:$false | Out-Null
            $script:CapturedMethod | Should -Be 'POST'
            $script:CapturedBody.detectionAction.Keys | Should -Not -Contain 'automatedActions'
            $script:CapturedBody.detectionAction.Keys | Should -Not -Contain 'organizationalScope'
            $script:CapturedBody.detectionAction.alertTemplate.Keys | Should -Not -Contain 'entityMappings'
        }

        It 'Should skip an unchanged rule returned in the dual old-plus-new shape' {
            $guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            Mock Get-CustomDetectionIdByDetectorId { return '48' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{
                    id              = '48'
                    detectorId      = 'f687512c-0654-4999-a0ac-d5906ffc3972'
                    displayName     = 'DUAL'
                    isEnabled       = $true
                    status          = 'enabled'
                    detectionAction = @{
                        alertTemplate    = @{
                            title           = 'Test'
                            description     = "Test [$guid]"
                            severity        = 'medium'
                            category        = 'DefenseEvasion'
                            mitreTechniques = @('T1562', 'T1562.001')
                            tactics         = @(@{ tactic = 'DefenseEvasion'; techniques = @(@{ technique = 'T1562'; subTechniques = @('T1562.001') }) })
                            impactedAssets  = @(@{ '@odata.type' = '#microsoft.graph.security.impactedDeviceAsset'; identifier = 'deviceId' })
                            entityMappings  = @{ hosts = @(@{ deviceIdColumn = 'DeviceId'; nameColumn = '' }); accounts = $null }
                        }
                        responseActions  = @(@{ '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'; identifier = 'deviceId'; isolationType = 'full' })
                        automatedActions = @{ isolateDevices = @(@{ deviceIdColumn = 'DeviceId'; isolationType = 'full' }); allowFiles = $null }
                    }
                    queryCondition  = @{ queryText = 'DeviceEvents' }
                    schedule        = @{ period = '1H'; frequency = 'PT1H' }
                }
            } -ModuleName XDRConverter

            $testYaml = @"
guid: $guid
ruleName: DUAL
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
mitreTechniques:
  - T1562.001
impactedEntities:
  - entityType: Machine
    entityIdentifier: DeviceId
actions:
  - actionType: IsolateMachine
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'body-dual.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Skipped'
            Should -Not -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter
        }

        It 'Should deploy a corpus-style file through the consumer call shape' {
            $testYaml = @"
actions:
- actionType: IsolateMachine
  additionalFields:
    isolationType: Full
alertCategory: InitialAccess
alertDescription: Desc
alertRecommendedAction: |
  Do things.
alertSeverity: High
alertTitle: '[X] Title'
frequency: 0
guid: 9b5a2396-03e3-4bdb-8355-8e3fb3a3d22d
impactedEntities:
- entityIdentifier: DeviceId
  entityType: Machine
- entityIdentifier: InitiatingProcessAccountUpn
  entityType: User
isEnabled: true
organizationalScope: []
queryText: |
  DeviceFileEvents
  | take 1
ruleName: CORPUS-Rule
"@
            $tempFile = Join-Path TestDrive: 'corpus.yml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $params = @{
                InputFile                    = $tempFile
                DescriptionTagPrefix         = 'PREFIX'
                SkipIdentifierValidation     = $true
                SkipMitreTechniqueValidation = $true
            }
            $result = Deploy-CustomDetection @params -Confirm:$false
            $result.Action | Should -Be 'Created'
            $script:CapturedBody.schedule.frequency | Should -Be 'PT0S'
            $script:CapturedBody.detectionAction.alertTemplate.description | Should -Match '\[PREFIX:9b5a2396-03e3-4bdb-8355-8e3fb3a3d22d\]$'
            $script:CapturedBody.detectionAction.alertTemplate.entityMappings.accounts[0].upnColumn | Should -Be 'InitiatingProcessAccountUpn'
            $script:CapturedBody.detectionAction.Keys | Should -Not -Contain 'organizationalScope'
        }
    }

    Context 'Create vs Update Logic' {

        It 'Should create a rule when it does not exist' {
            Mock Invoke-MgGraphRequest {
                return @{ id = 'new-id' }
            } -ModuleName XDRConverter

            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-New
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'create-new.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Created'
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter { $Method -eq 'POST' }
        }

        It 'Should update an existing rule when detectorId matches' {
            Mock Get-CustomDetectionIdByDetectorId { return 'existing-id' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{
                    id              = 'existing-id'
                    detectorId      = '81fb771a-c57e-41b8-9905-63dbf267c13f'
                    displayName     = 'OLD-NAME'
                    isEnabled       = $true
                    detectionAction = @{
                        alertTemplate = @{
                            title       = 'Old Title'
                            description = 'Old desc'
                            severity    = 'low'
                            category    = 'DefenseEvasion'
                        }
                    }
                    queryCondition  = @{ queryText = 'DeviceEvents | old' }
                    schedule        = @{ period = '0' }
                }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter

            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: PREFIX-TEST-Updated
isEnabled: true
alertTitle: New Title
frequency: 0
alertSeverity: Medium
alertDescription: New desc
alertCategory: DefenseEvasion
queryText: DeviceEvents | new
"@
            $tempFile = Join-Path TestDrive: 'update-existing.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Updated'
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter { $Method -eq 'PATCH' }
        }

        It 'Should skip update when rule has not changed' {
            $guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            Mock Get-CustomDetectionIdByDetectorId { return 'existing-id' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{
                    id              = 'existing-id'
                    detectorId      = $guid
                    displayName     = 'PREFIX-TEST'
                    isEnabled       = $true
                    detectionAction = @{
                        alertTemplate = @{
                            title       = 'Test'
                            description = "My desc [$guid]"
                            severity    = 'medium'
                            category    = 'DefenseEvasion'
                        }
                    }
                    queryCondition  = @{ queryText = 'DeviceEvents' }
                    schedule        = @{ period = '0' }
                }
            } -ModuleName XDRConverter

            $testYaml = @"
guid: $guid
ruleName: PREFIX-TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: My desc
alertCategory: DefenseEvasion
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'skip-nochange.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Skipped'
            $result.Reason | Should -Be 'No changes detected'
            Should -Not -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter
        }

        It 'Should update when only the response actions changed' {
            $guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            Mock Get-CustomDetectionIdByDetectorId { return 'existing-id' } -ModuleName XDRConverter
            Mock Get-CustomDetection {
                return @{
                    id              = 'existing-id'
                    detectorId      = $guid
                    displayName     = 'PREFIX-TEST'
                    isEnabled       = $true
                    detectionAction = @{
                        alertTemplate   = @{
                            title       = 'Test'
                            description = "My desc [$guid]"
                            severity    = 'medium'
                            category    = 'DefenseEvasion'
                        }
                        responseActions = @(
                            @{ '@odata.type' = '#microsoft.graph.security.isolateDeviceResponseAction'; identifier = 'deviceId'; isolationType = 'full' }
                        )
                    }
                    queryCondition  = @{ queryText = 'DeviceEvents' }
                    schedule        = @{ period = '0' }
                }
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter

            $testYaml = @"
guid: $guid
ruleName: PREFIX-TEST
isEnabled: true
alertTitle: Test
frequency: 0
alertSeverity: Medium
alertDescription: My desc
alertCategory: DefenseEvasion
actions:
  - actionType: RestrictAppExecution
queryText: DeviceEvents
"@
            $tempFile = Join-Path TestDrive: 'update-actions-only.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Updated'
            Should -Invoke Invoke-MgGraphRequest -ModuleName XDRConverter -ParameterFilter { $Method -eq 'PATCH' }
        }

        It 'Should find rule by description UUID tag when detectorId lookup fails' {
            $guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'
            # Return all detections with a matching description
            Mock Get-CustomDetection {
                if ($DetectionId) {
                    return @{
                        id              = 'found-by-desc'
                        detectorId      = 'different-detector'
                        displayName     = 'OLD-NAME'
                        isEnabled       = $false
                        detectionAction = @{
                            alertTemplate = @{
                                title       = 'Old Title'
                                description = "Some desc [$guid]"
                                severity    = 'low'
                                category    = 'DefenseEvasion'
                            }
                        }
                        queryCondition  = @{ queryText = 'DeviceEvents | old' }
                        schedule        = @{ period = '0' }
                    }
                }
                return @(
                    @{
                        id              = 'found-by-desc'
                        detectorId      = 'different-detector'
                        displayName     = 'OLD-NAME'
                        isEnabled       = $false
                        detectionAction = @{
                            alertTemplate = @{
                                title       = 'Old Title'
                                description = "Some desc [$guid]"
                                severity    = 'low'
                                category    = 'DefenseEvasion'
                            }
                        }
                        queryCondition  = @{ queryText = 'DeviceEvents | old' }
                        schedule        = @{ period = '0' }
                    }
                )
            } -ModuleName XDRConverter
            Mock Invoke-MgGraphRequest {} -ModuleName XDRConverter
            Mock Get-CustomDetectionIds {
                return @(
                    @{
                        Id = 'found-by-desc'
                        DetectorId = 'different-detector'
                        DescriptionTag = $guid
                        TagPrefix = $null
                    }
                )
            } -ModuleName XDRConverter

            $testYaml = @"
guid: $guid
ruleName: PREFIX-TEST-Remapped
isEnabled: true
alertTitle: New Title
frequency: 0
alertSeverity: Medium
alertDescription: New desc
alertCategory: DefenseEvasion
queryText: DeviceEvents | new
"@
            $tempFile = Join-Path TestDrive: 'find-by-desc.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Updated'
            $result.RuleId | Should -Be 'found-by-desc'
        }
    }

    Context 'MITRE Technique Validation' {

        It 'Should have SkipMitreTechniqueValidation switch parameter' {
            $cmd = Get-Command -Name 'Deploy-CustomDetection'
            $param = $cmd.Parameters['SkipMitreTechniqueValidation']
            $param | Should -Not -BeNullOrEmpty
            $param.ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It 'Should throw when a technique is not supported for the category' {
            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-MitreInvalid
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: Exfiltration
mitreTechniques:
  - T1041
  - T1059.001
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'mitre-invalid.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            { Deploy-CustomDetection -InputFile $tempFile -Confirm:$false } |
                Should -Throw '*not supported by XDR*'
        }

        It 'Should deploy successfully when all techniques are valid for the category' {
            Mock Invoke-MgGraphRequest { return @{ id = 'new-rule-id' } } -ModuleName XDRConverter

            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-MitreValid
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: Exfiltration
mitreTechniques:
  - T1041
  - T1048
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'mitre-valid.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -Confirm:$false
            $result.Action | Should -Be 'Created'
        }

        It 'Should bypass validation and deploy when -SkipMitreTechniqueValidation is set' {
            Mock Invoke-MgGraphRequest { return @{ id = 'new-rule-id' } } -ModuleName XDRConverter

            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-MitreSkip
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: Exfiltration
mitreTechniques:
  - T1041
  - T1059.001
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'mitre-skip.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            $result = Deploy-CustomDetection -InputFile $tempFile -SkipMitreTechniqueValidation -Confirm:$false
            $result.Action | Should -Be 'Created'
        }

        It 'Should deploy successfully when no mitreTechniques are defined' {
            Mock Invoke-MgGraphRequest { return @{ id = 'new-rule-id' } } -ModuleName XDRConverter

            $testYaml = @"
guid: 81fb771a-c57e-41b8-9905-63dbf267c13f
ruleName: TEST-MitreNone
isEnabled: true
alertTitle: Test
frequency: 1H
alertSeverity: Medium
alertDescription: Test
alertCategory: DefenseEvasion
queryText: DeviceEvents | take 1
"@
            $tempFile = Join-Path TestDrive: 'mitre-none.yaml'
            $testYaml | Out-File -FilePath $tempFile -Encoding UTF8

            { Deploy-CustomDetection -InputFile $tempFile -Confirm:$false } | Should -Not -Throw
        }
    }

    Context 'Help Documentation' {

        It 'Should have help documentation' {
            $help = Get-Help -Name 'Deploy-CustomDetection' -ErrorAction SilentlyContinue
            $help | Should -Not -BeNullOrEmpty
            $help.Synopsis | Should -Not -BeNullOrEmpty
        }

        It 'Should have examples' {
            $help = Get-Help -Name 'Deploy-CustomDetection' -ErrorAction SilentlyContinue
            $help.Examples | Should -Not -BeNullOrEmpty
        }
    }
}
