BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' 'src' 'XDRConverter.psd1'
    Import-Module $modulePath -Force
    $script:SchemaFile = Join-Path (Split-Path $PSScriptRoot -Parent) 'CustomDetection.schema.json'
    $script:BaseRule = @{ guid = '81fb771a-c57e-41b8-9905-63dbf267c13f'; ruleName = 'r'; alertTitle = 't'; frequency = 'PT1H'; alertSeverity = 'Low'; alertDescription = 'd'; alertCategory = 'Execution'; queryText = 'q' }
}

AfterAll {
    Remove-Module XDRConverter -ErrorAction SilentlyContinue
}

Describe 'CustomDetection schema' {

    It 'Accepts the id alias with and without the rule- prefix' {
        foreach ($id in @('81fb771a-c57e-41b8-9905-63dbf267c13f', 'rule-81fb771a-c57e-41b8-9905-63dbf267c13f')) {
            $rule = $script:BaseRule.Clone()
            $rule.Remove('guid')
            $rule.id = $id
            (Test-Json -Json ($rule | ConvertTo-Json) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeTrue -Because $id
        }
    }

    It 'Accepts a detectorId and rejects one that is not a uuid' {
        $rule = $script:BaseRule.Clone()
        $rule.detectorId = '7cb0d5af-690e-4f63-b4b9-6b40728cac5f'
        (Test-Json -Json ($rule | ConvertTo-Json) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeTrue
        $rule.detectorId = 'assigned-by-api'
        (Test-Json -Json ($rule | ConvertTo-Json) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeFalse
    }

    It 'Rejects an id that is not a uuid behind the prefix' {
        $rule = $script:BaseRule.Clone()
        $rule.Remove('guid')
        $rule.id = 'rule-not-a-uuid'
        (Test-Json -Json ($rule | ConvertTo-Json) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeFalse
    }

    It 'Lists the same columns per entity mapping collection as the module' {
        $schema = Get-Content $script:SchemaFile -Raw | ConvertFrom-Json -AsHashtable
        $collections = $schema.properties.entityMappings.properties
        $expected = InModuleScope XDRConverter { Get-CustomDetectionEntityMappingColumns }
        @($collections.Keys | Sort-Object) | Should -Be @($expected.Keys | Sort-Object)
        foreach ($name in $expected.Keys) {
            $schemaColumns = @($collections[$name].items.properties.Keys | Sort-Object)
            $schemaColumns | Should -Be @($expected[$name] | Sort-Object) -Because $name
            $collections[$name].items.additionalProperties | Should -BeFalse -Because $name
        }
    }

    It 'Accepts an empty mitreTechniques key the way the converter does' {
        $rule = $script:BaseRule.Clone()
        $rule.mitreTechniques = $null
        (Test-Json -Json ($rule | ConvertTo-Json) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeTrue
        InModuleScope XDRConverter -Parameters @{ Rule = $rule } {
            $body = ConvertFrom-CustomDetectionYamlToJson -YamlObject $Rule
            @($body.detectionAction.alertTemplate.tactics[0].Keys) | Should -Not -Contain 'techniques'
        }
    }

    It 'Rejects a column the collection does not document, as the converter does' {
        $rule = $script:BaseRule.Clone()
        $rule.entityMappings = @{ hosts = @(@{ bogusColumn = 'X' }) }
        (Test-Json -Json ($rule | ConvertTo-Json -Depth 5) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeFalse
        InModuleScope XDRConverter {
            { ConvertTo-CustomDetectionEntityMappings -EntityMappings @{ hosts = @(@{ bogusColumn = 'X' }) } } | Should -Throw '*bogusColumn*'
        }
    }

    It 'Accepts every documented column of every collection' {
        $expected = InModuleScope XDRConverter { Get-CustomDetectionEntityMappingColumns }
        foreach ($name in $expected.Keys) {
            $item = @{}
            foreach ($column in $expected[$name]) { $item[$column] = 'Col' }
            $rule = $script:BaseRule.Clone()
            $rule.entityMappings = @{ $name = @($item) }
            (Test-Json -Json ($rule | ConvertTo-Json -Depth 5) -SchemaFile $script:SchemaFile -ErrorAction SilentlyContinue) | Should -BeTrue -Because $name
        }
    }
}
