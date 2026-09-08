function ConvertTo-CustomDetectionFrequency {
    <#
    .SYNOPSIS
        Normalises a rule frequency to an ISO 8601 duration.

    .DESCRIPTION
        Accepts the legacy period tokens (0, 1H, 3H, 12H, 24H) as well as
        ISO 8601 durations and returns the ISO 8601 form expected by the
        schedule.frequency property.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    $text = "$Value".Trim()
    if ([string]::IsNullOrEmpty($text)) {
        throw 'The rule frequency is required.'
    }

    $legacyMap = @{
        '0'     = 'PT0S'
        '1H'    = 'PT1H'
        '3H'    = 'PT3H'
        '12H'   = 'PT12H'
        '24H'   = 'P1D'
        'PT24H' = 'P1D'
    }

    $key = $text.ToUpperInvariant()
    if ($legacyMap.ContainsKey($key)) {
        return $legacyMap[$key]
    }

    if ($key -match '^P(?=\d|T\d)(?:\d+W)?(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?$') {
        return $key
    }

    throw "Unsupported frequency '$text'. Use 0, 1H, 3H, 12H, 24H or an ISO 8601 duration such as PT1H."
}
