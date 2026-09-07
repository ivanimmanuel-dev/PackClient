[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PipeName,

    [ValidateSet('HappyPath', 'WrongMagic', 'UnexpectedType', 'TruncatedHeader', 'ZeroReadyDimensions', 'AbsurdReadyDimensions', 'NonzeroReadyPayload', 'TruncatedFramebuffer', 'MismatchedPayloadSize', 'AbsurdDimensions', 'NoPeerExpected')]
    [string]$Scenario = 'HappyPath',

    [ValidateRange(100, 300000)]
    [int]$ConnectTimeoutMs = 5000,

    [ValidateRange(100, 300000)]
    [int]$IoTimeoutMs = 5000
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop' -or
    $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1) {
    throw 'This kit requires Windows PowerShell 5.1 (powershell.exe).'
}
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw 'This kit requires a Windows PowerShell FullLanguage session.'
}

$Magic = [uint32]0x50435231
$HeaderLength = 20
$client = $null

function Get-LocalPipeComponent {
    param([string]$Value)
    $prefix = '\\.\pipe\'
    if (-not $Value.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PipeName must use the local \\.\pipe\ namespace'
    }
    $component = $Value.Substring($prefix.Length)
    if ([string]::IsNullOrWhiteSpace($component) -or $component.Length -gt 200 -or
        $component.Contains('\') -or $component.Contains('/') -or
        $component -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'PipeName must contain one bounded local pipe component'
    }
    return $component
}

function New-Bytes([int]$Length) { return ,([byte[]]::new($Length)) }

function Set-U32([byte[]]$Buffer, [int]$Offset, [uint32]$Value) {
    $Buffer[$Offset] = [byte]($Value -band 0xFF)
    $Buffer[$Offset + 1] = [byte](($Value -shr 8) -band 0xFF)
    $Buffer[$Offset + 2] = [byte](($Value -shr 16) -band 0xFF)
    $Buffer[$Offset + 3] = [byte](($Value -shr 24) -band 0xFF)
}

function Get-U32([byte[]]$Buffer, [int]$Offset) {
    return [uint32]([uint32]$Buffer[$Offset] -bor ([uint32]$Buffer[$Offset + 1] -shl 8) -bor
        ([uint32]$Buffer[$Offset + 2] -shl 16) -bor ([uint32]$Buffer[$Offset + 3] -shl 24))
}

function New-Header([uint32]$HeaderMagic, [uint32]$Type, [uint32]$Width, [uint32]$Height, [uint32]$PayloadSize) {
    $buffer = New-Bytes $HeaderLength
    Set-U32 $buffer 0 $HeaderMagic
    Set-U32 $buffer 4 $Type
    Set-U32 $buffer 8 $Width
    Set-U32 $buffer 12 $Height
    Set-U32 $buffer 16 $PayloadSize
    return ,$buffer
}

function Write-Exact([System.IO.Stream]$Stream, [byte[]]$Buffer, [int]$TimeoutMs, [string]$Label) {
    $async = $Stream.BeginWrite($Buffer, 0, $Buffer.Length, $null, $null)
    if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw "$Label write timed out" }
    $Stream.EndWrite($async)
    $Stream.Flush()
}

function Read-Exact([System.IO.Stream]$Stream, [int]$Length, [int]$TimeoutMs, [string]$Label) {
    $buffer = New-Bytes $Length
    $offset = 0
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($offset -lt $Length) {
        $remaining = $TimeoutMs - [int]$timer.ElapsedMilliseconds
        if ($remaining -le 0) { throw "$Label read timed out" }
        $async = $Stream.BeginRead($buffer, $offset, $Length - $offset, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($remaining)) { throw "$Label read timed out" }
        $count = $Stream.EndRead($async)
        if ($count -le 0) { throw "$Label was truncated" }
        $offset += $count
    }
    return ,$buffer
}

function Assert-Control([byte[]]$Header, [uint32]$Type) {
    if ((Get-U32 $Header 0) -ne $Magic -or (Get-U32 $Header 4) -ne $Type -or
        (Get-U32 $Header 8) -ne 0 -or (Get-U32 $Header 12) -ne 0 -or
        (Get-U32 $Header 16) -ne 0) {
        throw "unexpected peer control header; expected type $Type with zero fields"
    }
}

try {
    $component = Get-LocalPipeComponent $PipeName
    $client = New-Object -TypeName System.IO.Pipes.NamedPipeClientStream -ArgumentList @(
        '.', $component, [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::Asynchronous
    )
    try {
        $client.Connect($ConnectTimeoutMs)
    } catch [TimeoutException] {
        if ($Scenario -eq 'NoPeerExpected') {
            Write-Output 'SUCCESS expected local pipe connection timeout'
            exit 0
        }
        throw
    }
    if ($Scenario -eq 'NoPeerExpected') {
        throw 'NoPeerExpected unexpectedly connected'
    }

    if ($Scenario -eq 'TruncatedHeader') {
        $header = New-Header $Magic 1 2 2 0
        $partial = New-Bytes 7
        [Array]::Copy($header, $partial, 7)
        Write-Exact $client $partial $IoTimeoutMs 'truncated header'
        exit 0
    }
    if ($Scenario -eq 'WrongMagic') {
        Write-Exact $client (New-Header ([uint32]0x50435230) 1 2 2 0) $IoTimeoutMs 'wrong-magic header'
        exit 0
    }
    if ($Scenario -eq 'UnexpectedType') {
        Write-Exact $client (New-Header $Magic 9 2 2 0) $IoTimeoutMs 'unexpected-type header'
        exit 0
    }
    if ($Scenario -eq 'ZeroReadyDimensions') {
        Write-Exact $client (New-Header $Magic 1 0 2 0) $IoTimeoutMs 'zero-dimension type 1 header'
        exit 0
    }
    if ($Scenario -eq 'AbsurdReadyDimensions') {
        Write-Exact $client (New-Header $Magic 1 ([uint32]::MaxValue) 2 0) $IoTimeoutMs 'absurd-dimension type 1 header'
        exit 0
    }
    if ($Scenario -eq 'NonzeroReadyPayload') {
        Write-Exact $client (New-Header $Magic 1 2 2 1) $IoTimeoutMs 'nonzero-payload type 1 header'
        exit 0
    }

    Write-Exact $client (New-Header $Magic 1 2 2 0) $IoTimeoutMs 'type 1 header'
    $request = Read-Exact $client $HeaderLength $IoTimeoutMs 'type 3 header'
    Assert-Control $request 3

    if ($Scenario -eq 'MismatchedPayloadSize') {
        Write-Exact $client (New-Header $Magic 2 2 2 12) $IoTimeoutMs 'mismatched type 2 header'
        exit 0
    }
    if ($Scenario -eq 'AbsurdDimensions') {
        Write-Exact $client (New-Header $Magic 2 ([uint32]::MaxValue) ([uint32]::MaxValue) ([uint32]::MaxValue)) $IoTimeoutMs 'absurd type 2 header'
        exit 0
    }

    $pixels = [byte[]](
        0x00, 0x00, 0xFF, 0x00,
        0x00, 0xFF, 0x00, 0x00,
        0xFF, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0x00
    )
    Write-Exact $client (New-Header $Magic 2 2 2 16) $IoTimeoutMs 'type 2 header'
    if ($Scenario -eq 'TruncatedFramebuffer') {
        $partial = New-Bytes 8
        [Array]::Copy($pixels, $partial, 8)
        Write-Exact $client $partial $IoTimeoutMs 'truncated framebuffer'
        exit 0
    }
    Write-Exact $client $pixels $IoTimeoutMs 'framebuffer'

    $exitHeader = Read-Exact $client $HeaderLength $IoTimeoutMs 'type 5 header'
    Assert-Control $exitHeader 5
    Write-Output 'SUCCESS synthetic worker completed type 1 -> 3 -> 2 -> 5'
    exit 0
} catch {
    Write-Error ('FAILURE: ' + $_.Exception.Message)
    exit 1
} finally {
    if ($null -ne $client) {
        try { $client.Dispose() } catch { }
    }
}
