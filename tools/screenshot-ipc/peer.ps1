<#
Runs a local validation peer for the reconstructed 1RCP screenshot protocol.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PipeName,

    [string]$EvidenceRoot = (Join-Path $PSScriptRoot 'evidence'),

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')]
    [string]$RunId,

    [ValidateRange(100, 300000)]
    [int]$ConnectTimeoutMs = 15000,

    [ValidateRange(100, 300000)]
    [int]$IoTimeoutMs = 10000,

    [ValidateRange(1, 32768)]
    [int]$MaxWidth = 8192,

    [ValidateRange(1, 32768)]
    [int]$MaxHeight = 8192,

    [ValidateRange(4, 1073741824)]
    [int64]$MaxFramebufferBytes = 134217728
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
$script:Events = @()
$script:Pipe = $null
$script:EvidenceDirectory = $null
$script:StartUtc = [DateTime]::UtcNow
$script:FramebufferHash = $null
$script:FramebufferSize = $null
$script:FramebufferWidth = $null
$script:FramebufferHeight = $null

function Get-UtcTimestamp {
    [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
}

function Add-Event {
    param(
        [Parameter(Mandatory = $true)][string]$Event,
        [string]$Direction,
        [Nullable[uint32]]$Type,
        [Nullable[uint32]]$MagicValue,
        [Nullable[uint32]]$Width,
        [Nullable[uint32]]$Height,
        [Nullable[uint32]]$PayloadSize,
        [Nullable[uint64]]$ExpectedPayloadSize,
        [Nullable[uint64]]$ActualPayloadSize,
        [string]$Detail
    )

    if ($script:Events.Count -ge 64) {
        throw 'internal transcript event limit exceeded'
    }
    $script:Events += [pscustomobject][ordered]@{
        timestamp_utc        = Get-UtcTimestamp
        event                = $Event
        direction            = $Direction
        type                 = if ($null -eq $Type) { $null } else { [uint32]$Type }
        magic                = if ($null -eq $MagicValue) { $null } else { ('0x{0:X8}' -f [uint32]$MagicValue) }
        width                = if ($null -eq $Width) { $null } else { [uint32]$Width }
        height               = if ($null -eq $Height) { $null } else { [uint32]$Height }
        payload_size         = if ($null -eq $PayloadSize) { $null } else { [uint32]$PayloadSize }
        expected_payload_size = if ($null -eq $ExpectedPayloadSize) { $null } else { [uint64]$ExpectedPayloadSize }
        actual_payload_size  = if ($null -eq $ActualPayloadSize) { $null } else { [uint64]$ActualPayloadSize }
        detail               = $Detail
    }
}

function Get-LocalPipeComponent {
    param([Parameter(Mandatory = $true)][string]$Value)

    $prefix = '\\.\pipe\'
    if (-not $Value.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PipeName must use the local \\.\pipe\ namespace'
    }
    $component = $Value.Substring($prefix.Length)
    if ([string]::IsNullOrWhiteSpace($component) -or
        $component.Length -gt 200 -or
        $component.Contains('\') -or
        $component.Contains('/') -or
        $component -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
        throw 'PipeName must contain one bounded local pipe component'
    }
    return $component
}

function New-ExactByteArray {
    param([Parameter(Mandatory = $true)][int]$Length)
    return ,([byte[]]::new($Length))
}

function Read-Exact {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][int]$Length,
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $buffer = New-ExactByteArray -Length $Length
    $offset = 0
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($offset -lt $Length) {
        $remainingMs = $TimeoutMs - [int]$timer.ElapsedMilliseconds
        if ($remainingMs -le 0) {
            throw "$Label read timed out after $TimeoutMs ms (expected $Length bytes, received $offset)"
        }
        $async = $Stream.BeginRead($buffer, $offset, $Length - $offset, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($remainingMs)) {
            throw "$Label read timed out after $TimeoutMs ms (expected $Length bytes, received $offset)"
        }
        $count = $Stream.EndRead($async)
        if ($count -le 0) {
            throw "$Label was truncated (expected $Length bytes, received $offset)"
        }
        $offset += $count
    }
    return ,$buffer
}

function Write-Exact {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][byte[]]$Buffer,
        [Parameter(Mandatory = $true)][int]$TimeoutMs,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $async = $Stream.BeginWrite($Buffer, 0, $Buffer.Length, $null, $null)
    if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
        throw "$Label write timed out after $TimeoutMs ms"
    }
    $Stream.EndWrite($async)
    $Stream.Flush()
}

function Read-UInt32LE {
    param([byte[]]$Buffer, [int]$Offset)
    return [uint32](
        [uint32]$Buffer[$Offset] -bor
        ([uint32]$Buffer[$Offset + 1] -shl 8) -bor
        ([uint32]$Buffer[$Offset + 2] -shl 16) -bor
        ([uint32]$Buffer[$Offset + 3] -shl 24)
    )
}

function Write-UInt32LE {
    param([byte[]]$Buffer, [int]$Offset, [uint32]$Value)
    $Buffer[$Offset] = [byte]($Value -band 0xFF)
    $Buffer[$Offset + 1] = [byte](($Value -shr 8) -band 0xFF)
    $Buffer[$Offset + 2] = [byte](($Value -shr 16) -band 0xFF)
    $Buffer[$Offset + 3] = [byte](($Value -shr 24) -band 0xFF)
}

function ConvertFrom-Header {
    param([Parameter(Mandatory = $true)][byte[]]$Buffer)
    if ($Buffer.Length -ne $HeaderLength) {
        throw 'internal header length error'
    }
    return [pscustomobject][ordered]@{
        magic        = Read-UInt32LE $Buffer 0
        type         = Read-UInt32LE $Buffer 4
        width        = Read-UInt32LE $Buffer 8
        height       = Read-UInt32LE $Buffer 12
        payload_size = Read-UInt32LE $Buffer 16
    }
}

function New-Header {
    param([uint32]$Type)
    $buffer = New-ExactByteArray -Length $HeaderLength
    Write-UInt32LE $buffer 0 $Magic
    Write-UInt32LE $buffer 4 $Type
    return ,$buffer
}

function Assert-HeaderIdentity {
    param(
        [Parameter(Mandatory = $true)]$Header,
        [Parameter(Mandatory = $true)][uint32]$ExpectedType,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ([uint32]$Header.magic -ne $Magic) {
        throw ('{0} has wrong magic 0x{1:X8}' -f $Label, [uint32]$Header.magic)
    }
    if ([uint32]$Header.type -ne $ExpectedType) {
        throw ("$Label has unexpected type {0}; expected {1}" -f [uint32]$Header.type, $ExpectedType)
    }
}

function Assert-BoundedDimensions {
    param(
        [Parameter(Mandatory = $true)]$Header,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $width = [uint64][uint32]$Header.width
    $height = [uint64][uint32]$Header.height
    if ($width -eq 0 -or $height -eq 0) {
        throw "$Label dimensions must be positive"
    }
    if ($width -gt [uint64]$MaxWidth -or $height -gt [uint64]$MaxHeight) {
        throw "$Label dimensions exceed limits ($width x $height; limits $MaxWidth x $MaxHeight)"
    }
}

function Get-CheckedFramebufferSize {
    param([Parameter(Mandatory = $true)]$Header)

    Assert-BoundedDimensions -Header $Header -Label 'framebuffer'
    $width = [uint64][uint32]$Header.width
    $height = [uint64][uint32]$Header.height
    if ($height -ne 0 -and $width -gt ([uint64]::MaxValue / $height)) {
        throw 'framebuffer width*height integer overflow'
    }
    $pixels = [uint64]($width * $height)
    if ($pixels -gt ([uint64]::MaxValue / 4)) {
        throw 'framebuffer byte-size integer overflow'
    }
    $bytes = [uint64]($pixels * 4)
    if ($bytes -gt [uint64]$MaxFramebufferBytes -or $bytes -gt [uint64][int]::MaxValue) {
        throw "framebuffer allocation exceeds limit ($bytes bytes; limit $MaxFramebufferBytes)"
    }
    return $bytes
}

function Set-Int32LE {
    param([byte[]]$Buffer, [int]$Offset, [int32]$Value)
    $unsigned = if ($Value -lt 0) {
        [uint32]([int64]$Value + 4294967296)
    } else {
        [uint32]$Value
    }
    Write-UInt32LE $Buffer $Offset $unsigned
}

function New-BmpBytes {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Pixels,
        [Parameter(Mandatory = $true)][int]$Width,
        [Parameter(Mandatory = $true)][int]$Height
    )

    $pixelOffset = 54
    $fileSize64 = [int64]$pixelOffset + [int64]$Pixels.Length
    if ($fileSize64 -gt [uint32]::MaxValue) {
        throw 'BMP file size exceeds format limit'
    }
    $bmp = New-ExactByteArray -Length ([int]$fileSize64)
    $bmp[0] = [byte][char]'B'
    $bmp[1] = [byte][char]'M'
    Write-UInt32LE $bmp 2 ([uint32]$fileSize64)
    Write-UInt32LE $bmp 10 ([uint32]$pixelOffset)
    Write-UInt32LE $bmp 14 ([uint32]40)
    Set-Int32LE $bmp 18 ([int32]$Width)
    Set-Int32LE $bmp 22 ([int32](-$Height))
    $bmp[26] = 1
    $bmp[28] = 32
    Write-UInt32LE $bmp 34 ([uint32]$Pixels.Length)
    [Array]::Copy($Pixels, 0, $bmp, $pixelOffset, $Pixels.Length)
    return ,$bmp
}

function New-PipeServer {
    param([Parameter(Mandatory = $true)][string]$Component)

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User) {
        throw 'cannot determine current Windows identity for pipe ACL'
    }
    $security = New-Object System.IO.Pipes.PipeSecurity
    $security.SetOwner($identity.User)
    # Grant the current user read/write access and reject network-logon clients.
    # WindowsIdentity.Groups does not reliably expose the dynamic logon SID.
    $networkSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-2'
    $denyNetwork = New-Object -TypeName System.IO.Pipes.PipeAccessRule -ArgumentList @(
        $networkSid,
        [System.IO.Pipes.PipeAccessRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Deny
    )
    $security.AddAccessRule($denyNetwork)
    $rule = New-Object -TypeName System.IO.Pipes.PipeAccessRule -ArgumentList @(
        $identity.User,
        [System.IO.Pipes.PipeAccessRights]::ReadWrite,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $security.SetAccessRule($rule)

    return (New-Object -TypeName System.IO.Pipes.NamedPipeServerStream -ArgumentList @(
        $Component,
        [System.IO.Pipes.PipeDirection]::InOut,
        1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte,
        [System.IO.Pipes.PipeOptions]::Asynchronous,
        4096,
        4096,
        $security
    ))
}

function Initialize-EvidenceDirectory {
    if ([string]::IsNullOrWhiteSpace($RunId)) {
        $script:RunId = '{0}-{1}' -f $script:StartUtc.ToString('yyyyMMddTHHmmss.fffZ'), ([Guid]::NewGuid().ToString('N').Substring(0, 8))
    } else {
        $script:RunId = $RunId
    }
    $fullRoot = [IO.Path]::GetFullPath($EvidenceRoot)
    if ($fullRoot.StartsWith('\\')) {
        throw 'EvidenceRoot must be a local filesystem path'
    }
    if (-not (Test-Path -LiteralPath $fullRoot)) {
        New-Item -ItemType Directory -Path $fullRoot | Out-Null
    }
    $resolvedRoot = Resolve-Path -LiteralPath $fullRoot
    if ($resolvedRoot.Provider.Name -ne 'FileSystem') {
        throw 'EvidenceRoot must use the filesystem provider'
    }
    $root = $resolvedRoot.ProviderPath
    if ($root.StartsWith('\\')) {
        throw 'EvidenceRoot must not be a UNC path'
    }
    $candidate = Join-Path $root $script:RunId
    if (Test-Path -LiteralPath $candidate) {
        throw "evidence directory already exists: $candidate"
    }
    New-Item -ItemType Directory -Path $candidate | Out-Null
    # Finalization may write only to a directory this invocation created.
    $script:EvidenceDirectory = $candidate
}

function Write-Evidence {
    param([bool]$Success, [string]$Reason)

    if ($null -eq $script:EvidenceDirectory) {
        return
    }
    $endUtc = [DateTime]::UtcNow
    $sequence = @($script:Events | Where-Object { $_.event -eq 'message' } | ForEach-Object { '{0}:{1}' -f $_.direction, $_.type }) -join ','
    $summary = @(
        'tool=packclient-screenshot-ipc'
        ('status={0}' -f $(if ($Success) { 'SUCCESS' } else { 'FAILURE' }))
        ('reason={0}' -f $Reason)
        ('pipe_name={0}' -f $PipeName)
        ('run_id={0}' -f $script:RunId)
        ('start_utc={0}' -f $script:StartUtc.ToString('o', [Globalization.CultureInfo]::InvariantCulture))
        ('end_utc={0}' -f $endUtc.ToString('o', [Globalization.CultureInfo]::InvariantCulture))
        ('connect_timeout_ms={0}' -f $ConnectTimeoutMs)
        ('io_timeout_ms={0}' -f $IoTimeoutMs)
        ('max_width={0}' -f $MaxWidth)
        ('max_height={0}' -f $MaxHeight)
        ('max_framebuffer_bytes={0}' -f $MaxFramebufferBytes)
        ('message_sequence={0}' -f $sequence)
        ('framebuffer_width={0}' -f $script:FramebufferWidth)
        ('framebuffer_height={0}' -f $script:FramebufferHeight)
        ('framebuffer_size={0}' -f $script:FramebufferSize)
        ('framebuffer_sha256={0}' -f $script:FramebufferHash)
    )
    Set-Content -LiteralPath (Join-Path $script:EvidenceDirectory 'run-summary.txt') -Value $summary -Encoding UTF8

    $json = @($script:Events) | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath (Join-Path $script:EvidenceDirectory 'transcript.json') -Value $json -Encoding UTF8
    $text = @($script:Events | ForEach-Object {
        '{0} event={1} direction={2} type={3} magic={4} width={5} height={6} payload_size={7} expected_payload_size={8} actual_payload_size={9} detail={10}' -f
            $_.timestamp_utc, $_.event, $_.direction, $_.type, $_.magic, $_.width, $_.height,
            $_.payload_size, $_.expected_payload_size, $_.actual_payload_size, $_.detail
    })
    Set-Content -LiteralPath (Join-Path $script:EvidenceDirectory 'transcript.txt') -Value $text -Encoding UTF8

    $hashTargets = Get-ChildItem -LiteralPath $script:EvidenceDirectory -File |
        Where-Object { $_.Name -ne 'hashes.sha256' } |
        Sort-Object Name
    $hashLines = @($hashTargets | ForEach-Object {
        '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant(), $_.Name
    })
    Set-Content -LiteralPath (Join-Path $script:EvidenceDirectory 'hashes.sha256') -Value $hashLines -Encoding ASCII
}

$success = $false
$reason = 'uninitialized'
try {
    $component = Get-LocalPipeComponent -Value $PipeName
    Initialize-EvidenceDirectory
    Add-Event -Event 'state' -Detail 'evidence directory created'

    $script:Pipe = New-PipeServer -Component $component
    Add-Event -Event 'state' -Detail 'current-user pipe created with network-logon denial; waiting for one local client'
    $wait = $script:Pipe.BeginWaitForConnection($null, $null)
    if (-not $wait.AsyncWaitHandle.WaitOne($ConnectTimeoutMs)) {
        throw "pipe connection timed out after $ConnectTimeoutMs ms"
    }
    $script:Pipe.EndWaitForConnection($wait)
    Add-Event -Event 'state' -Detail 'client connected'

    $readyBytes = Read-Exact -Stream $script:Pipe -Length $HeaderLength -TimeoutMs $IoTimeoutMs -Label 'type 1 header'
    $ready = ConvertFrom-Header $readyBytes
    Add-Event -Event 'message' -Direction 'worker_to_peer' -Type $ready.type -MagicValue $ready.magic -Width $ready.width -Height $ready.height -PayloadSize $ready.payload_size -ExpectedPayloadSize 0 -ActualPayloadSize 0 -Detail 'ready metadata'
    Assert-HeaderIdentity -Header $ready -ExpectedType 1 -Label 'initial worker message'
    if ([uint32]$ready.payload_size -ne 0) {
        throw 'type 1 payload_size must be zero'
    }
    Assert-BoundedDimensions -Header $ready -Label 'type 1 ready'
    Add-Event -Event 'validation' -Direction 'worker_to_peer' -Type 1 -Width $ready.width -Height $ready.height -PayloadSize $ready.payload_size -ExpectedPayloadSize 0 -ActualPayloadSize 0 -Detail 'ready dimensions are positive and within configured bounds; payload size is zero'

    $request = New-Header -Type 3
    Write-Exact -Stream $script:Pipe -Buffer $request -TimeoutMs $IoTimeoutMs -Label 'type 3 header'
    Add-Event -Event 'message' -Direction 'peer_to_worker' -Type 3 -MagicValue $Magic -Width 0 -Height 0 -PayloadSize 0 -ExpectedPayloadSize 0 -ActualPayloadSize 0 -Detail 'recapture request'

    $frameHeaderBytes = Read-Exact -Stream $script:Pipe -Length $HeaderLength -TimeoutMs $IoTimeoutMs -Label 'type 2 header'
    $frameHeader = ConvertFrom-Header $frameHeaderBytes
    Add-Event -Event 'message' -Direction 'worker_to_peer' -Type $frameHeader.type -MagicValue $frameHeader.magic -Width $frameHeader.width -Height $frameHeader.height -PayloadSize $frameHeader.payload_size -Detail 'framebuffer header'
    Assert-HeaderIdentity -Header $frameHeader -ExpectedType 2 -Label 'capture response'
    $expectedSize = Get-CheckedFramebufferSize -Header $frameHeader
    Add-Event -Event 'validation' -Direction 'worker_to_peer' -Type 2 -Width $frameHeader.width -Height $frameHeader.height -PayloadSize $frameHeader.payload_size -ExpectedPayloadSize $expectedSize -ActualPayloadSize ([uint64][uint32]$frameHeader.payload_size) -Detail 'declared payload size compared with checked width*height*4'
    if ([uint64][uint32]$frameHeader.payload_size -ne $expectedSize) {
        throw "type 2 payload_size mismatch (header $($frameHeader.payload_size), expected $expectedSize)"
    }

    $pixels = Read-Exact -Stream $script:Pipe -Length ([int]$expectedSize) -TimeoutMs $IoTimeoutMs -Label 'type 2 framebuffer'
    Add-Event -Event 'payload' -Direction 'worker_to_peer' -Type 2 -Width $frameHeader.width -Height $frameHeader.height -PayloadSize $frameHeader.payload_size -ExpectedPayloadSize $expectedSize -ActualPayloadSize $pixels.Length -Detail 'raw BGRX framebuffer received exactly'
    $rawPath = Join-Path $script:EvidenceDirectory 'framebuffer.bgrx'
    [IO.File]::WriteAllBytes($rawPath, $pixels)
    $script:FramebufferHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $rawPath).Hash.ToUpperInvariant()
    $script:FramebufferSize = $pixels.Length
    $script:FramebufferWidth = [uint32]$frameHeader.width
    $script:FramebufferHeight = [uint32]$frameHeader.height

    $bmp = New-BmpBytes -Pixels $pixels -Width ([int]$frameHeader.width) -Height ([int]$frameHeader.height)
    [IO.File]::WriteAllBytes((Join-Path $script:EvidenceDirectory 'framebuffer.bmp'), $bmp)
    Add-Event -Event 'artifact' -ActualPayloadSize $pixels.Length -Detail "framebuffer SHA-256 $script:FramebufferHash; raw BGRX and top-down BMP saved"

    $exitHeader = New-Header -Type 5
    Write-Exact -Stream $script:Pipe -Buffer $exitHeader -TimeoutMs $IoTimeoutMs -Label 'type 5 header'
    Add-Event -Event 'message' -Direction 'peer_to_worker' -Type 5 -MagicValue $Magic -Width 0 -Height 0 -PayloadSize 0 -ExpectedPayloadSize 0 -ActualPayloadSize 0 -Detail 'exit request'

    $success = $true
    $reason = 'validated type 1 -> 3 -> 2 -> 5 sequence'
} catch {
    $reason = $_.Exception.Message
    try { Add-Event -Event 'error' -Detail $reason } catch { }
} finally {
    if ($null -ne $script:Pipe) {
        try { $script:Pipe.Dispose() } catch { }
    }
    try { Write-Evidence -Success $success -Reason $reason } catch {
        if ($success) {
            $success = $false
            $reason = 'evidence finalization failed: ' + $_.Exception.Message
        }
    }
}

if ($success) {
    Write-Output "SUCCESS evidence=$script:EvidenceDirectory"
    exit 0
}
Write-Error "FAILURE: $reason"
if ($null -ne $script:EvidenceDirectory) {
    Write-Output "evidence=$script:EvidenceDirectory"
}
exit 1
