[CmdletBinding()]
param(
    [switch]$KeepArtifacts,
    [string]$ArtifactParent = ([IO.Path]::GetTempPath())
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


$KitRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\screenshot-ipc'
$PeerScript = Join-Path $KitRoot 'peer.ps1'
$WorkerScript = Join-Path $KitRoot 'simulator.ps1'
$PowerShellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$TestParent = [IO.Path]::GetFullPath($ArtifactParent)
if ($TestParent.StartsWith('\\') -or -not (Test-Path -LiteralPath $TestParent -PathType Container)) {
    throw 'ArtifactParent must be an existing local directory'
}
$TestRoot = Join-Path $TestParent ('packclient-screenshot-ipc-tests-' + [Guid]::NewGuid().ToString('N'))
$script:Passed = 0

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "assertion failed: $Message" }
}

function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -cne $Expected) { throw "assertion failed: $Message (actual=[$Actual], expected=[$Expected])" }
}

function Pass([string]$Name) {
    $script:Passed++
    Write-Output "PASS $Name"
}

function Start-HiddenPowerShell([string]$Arguments) {
    $logPrefix = Join-Path $TestRoot ('process-' + [Guid]::NewGuid().ToString('N'))
    $process = Start-Process -FilePath $PowerShellExe -ArgumentList $Arguments -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput ($logPrefix + '.stdout.txt') -RedirectStandardError ($logPrefix + '.stderr.txt')
    # Cache the native handle before a redirected child can exit. Without it,
    # Windows PowerShell may expose a null ExitCode after WaitForExit.
    $null = $process.Handle
    return $process
}

function Wait-Checked([Diagnostics.Process]$Process, [int]$TimeoutMs, [string]$Label) {
    if (-not $Process.WaitForExit($TimeoutMs)) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        throw "$Label exceeded test timeout"
    }
    $exitCode = $Process.ExitCode
    if ($null -eq $exitCode) { throw "$Label did not expose a process exit code" }
    return $exitCode
}

function Invoke-ProtocolCase([string]$Name, [string]$Scenario, [int]$ExpectedPeerExit) {
    $caseRoot = Join-Path $TestRoot $Name
    $evidenceRoot = Join-Path $caseRoot 'evidence'
    New-Item -ItemType Directory -Path $caseRoot | Out-Null
    $pipeName = '\\.\pipe\packclient-1rcp-test-' + [Guid]::NewGuid().ToString('N')
    $runId = 'test-run'

    $peerArgs = '-NoProfile -NonInteractive -File "{0}" -PipeName "{1}" -EvidenceRoot "{2}" -RunId "{3}" -ConnectTimeoutMs 3000 -IoTimeoutMs 3000 -MaxWidth 64 -MaxHeight 64 -MaxFramebufferBytes 16384' -f
        $PeerScript, $pipeName, $evidenceRoot, $runId
    $workerArgs = '-NoProfile -NonInteractive -File "{0}" -PipeName "{1}" -Scenario {2} -ConnectTimeoutMs 3000 -IoTimeoutMs 3000' -f
        $WorkerScript, $pipeName, $Scenario

    $peer = Start-HiddenPowerShell $peerArgs
    $worker = $null
    try {
        $worker = Start-HiddenPowerShell $workerArgs
        $workerExit = Wait-Checked $worker 10000 "$Name worker"
        $peerExit = Wait-Checked $peer 10000 "$Name peer"
        if ($ExpectedPeerExit -eq 0) {
            Assert-Equal $workerExit 0 "$Name synthetic worker exit"
        } else {
            Assert-True ($workerExit -eq 0 -or $workerExit -eq 1) "$Name malformed sender bounded exit"
        }
        Assert-Equal $peerExit $ExpectedPeerExit "$Name peer exit"
    } finally {
        foreach ($process in @($worker, $peer)) {
            if ($null -ne $process -and -not $process.HasExited) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            }
            if ($null -ne $process) { $process.Dispose() }
        }
    }
    return [pscustomobject]@{
        Directory = Join-Path $evidenceRoot $runId
        PipeName = $pipeName
    }
}

function Get-Summary([string]$Directory) {
    return Get-Content -Raw -LiteralPath (Join-Path $Directory 'run-summary.txt')
}

New-Item -ItemType Directory -Path $TestRoot | Out-Null
try {
    $happy1 = Invoke-ProtocolCase 'happy-one' 'HappyPath' 0
    $expectedFiles = @('framebuffer.bgrx', 'framebuffer.bmp', 'hashes.sha256', 'run-summary.txt', 'transcript.json', 'transcript.txt')
    $actualFiles = @(Get-ChildItem -LiteralPath $happy1.Directory -File | Sort-Object Name | Select-Object -ExpandProperty Name)
    $expectedFileText = @($expectedFiles | Sort-Object) -join ','
    Assert-Equal ($actualFiles -join ',') $expectedFileText 'successful evidence file set'
    $summary = Get-Summary $happy1.Directory
    Assert-True ($summary.Contains('status=SUCCESS')) 'happy summary status'
    Assert-True ($summary.Contains('message_sequence=worker_to_peer:1,peer_to_worker:3,worker_to_peer:2,peer_to_worker:5')) 'exact protocol sequence'
    $rawHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $happy1.Directory 'framebuffer.bgrx')).Hash
    Assert-Equal $rawHash '51E73B32547F29FA45D01B01CB92236AC641E1EA40F8E974AD9846E0954FB198' 'known BGRX hash'
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $happy1.Directory 'hashes.sha256')
    Assert-True ($manifest.Contains($rawHash.ToLowerInvariant() + '  framebuffer.bgrx')) 'raw hash manifest entry'
    Pass 'happy-path type 1 -> 3 -> 2 -> 5'

    $bmpPath = Join-Path $happy1.Directory 'framebuffer.bmp'
    $bmp = [IO.File]::ReadAllBytes($bmpPath)
    Assert-Equal $bmp.Length 70 'BMP size'
    Assert-Equal ([Text.Encoding]::ASCII.GetString($bmp, 0, 2)) 'BM' 'BMP signature'
    Assert-Equal ([BitConverter]::ToUInt32($bmp, 10)) ([uint32]54) 'BMP pixel offset'
    Assert-Equal ([BitConverter]::ToInt32($bmp, 18)) 2 'BMP width'
    Assert-Equal ([BitConverter]::ToInt32($bmp, 22)) (-2) 'BMP top-down height'
    Assert-Equal ([BitConverter]::ToUInt16($bmp, 28)) ([uint16]32) 'BMP bit depth'
    Assert-Equal ([BitConverter]::ToUInt32($bmp, 30)) ([uint32]0) 'BMP BI_RGB compression'
    Assert-Equal (Get-FileHash -Algorithm SHA256 -LiteralPath $bmpPath).Hash 'ADD262002A71D6F04080E52A8ED726BD962BF12313112EFA3E3FBB65F3AA4595' 'known BMP hash'
    Assert-True ($manifest.Contains('add262002a71d6f04080e52a8ed726bd962bf12313112efa3e3fbb65f3aa4595  framebuffer.bmp')) 'BMP hash manifest entry'
    $raw = [IO.File]::ReadAllBytes((Join-Path $happy1.Directory 'framebuffer.bgrx'))
    for ($index = 0; $index -lt $raw.Length; $index++) {
        Assert-Equal $bmp[54 + $index] $raw[$index] "BMP BGRX byte $index"
    }
    Pass 'correct top-down image reconstruction from known BGRX pixels'

    $happy2 = Invoke-ProtocolCase 'happy-two' 'HappyPath' 0
    Assert-Equal (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $happy2.Directory 'framebuffer.bgrx')).Hash $rawHash 'raw output determinism'
    Assert-Equal (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $happy2.Directory 'framebuffer.bmp')).Hash 'ADD262002A71D6F04080E52A8ED726BD962BF12313112EFA3E3FBB65F3AA4595' 'BMP output determinism'
    Pass 'deterministic framebuffer and BMP hashes'

    $negativeCases = @(
        @('wrong-magic', 'WrongMagic', 'wrong magic'),
        @('unexpected-type', 'UnexpectedType', 'unexpected type'),
        @('truncated-header', 'TruncatedHeader', 'truncated'),
        @('zero-ready-dimensions', 'ZeroReadyDimensions', 'type 1 ready dimensions must be positive'),
        @('absurd-ready-dimensions', 'AbsurdReadyDimensions', 'type 1 ready dimensions exceed limits'),
        @('nonzero-ready-payload', 'NonzeroReadyPayload', 'type 1 payload_size must be zero'),
        @('truncated-framebuffer', 'TruncatedFramebuffer', 'truncated'),
        @('mismatched-payload', 'MismatchedPayloadSize', 'payload_size mismatch'),
        @('absurd-dimensions', 'AbsurdDimensions', 'dimensions exceed limits')
    )
    foreach ($case in $negativeCases) {
        $result = Invoke-ProtocolCase $case[0] $case[1] 1
        $failureSummary = Get-Summary $result.Directory
        Assert-True ($failureSummary.Contains('status=FAILURE')) "$($case[0]) failure status"
        Assert-True ($failureSummary.Contains($case[2])) "$($case[0]) failure reason"
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $result.Directory 'framebuffer.bgrx'))) "$($case[0]) did not materialize framebuffer"
        Pass $case[0]
    }

    $timeoutRoot = Join-Path $TestRoot 'peer-timeout'
    $timeoutEvidence = Join-Path $timeoutRoot 'evidence'
    New-Item -ItemType Directory -Path $timeoutRoot | Out-Null
    $timeoutPipe = '\\.\pipe\packclient-1rcp-test-' + [Guid]::NewGuid().ToString('N')
    $timeoutArgs = '-NoProfile -NonInteractive -File "{0}" -PipeName "{1}" -EvidenceRoot "{2}" -RunId timeout-run -ConnectTimeoutMs 300 -IoTimeoutMs 300' -f
        $PeerScript, $timeoutPipe, $timeoutEvidence
    $timeoutPeer = Start-HiddenPowerShell $timeoutArgs
    try { Assert-Equal (Wait-Checked $timeoutPeer 5000 'peer timeout') 1 'no-worker peer exit' } finally { $timeoutPeer.Dispose() }
    Assert-True ((Get-Summary (Join-Path $timeoutEvidence 'timeout-run')).Contains('connection timed out')) 'no-worker timeout reason'
    Pass 'finite peer connection timeout with no worker'

    $noPeerPipe = '\\.\pipe\packclient-1rcp-test-' + [Guid]::NewGuid().ToString('N')
    $noPeerArgs = '-NoProfile -NonInteractive -File "{0}" -PipeName "{1}" -Scenario NoPeerExpected -ConnectTimeoutMs 300 -IoTimeoutMs 300' -f
        $WorkerScript, $noPeerPipe
    $noPeerWorker = Start-HiddenPowerShell $noPeerArgs
    try { Assert-Equal (Wait-Checked $noPeerWorker 5000 'no-peer worker') 0 'synthetic worker no-peer timeout' } finally { $noPeerWorker.Dispose() }
    Pass 'finite synthetic-worker timeout with no peer'

    $before = @(Get-ChildItem -LiteralPath $happy1.Directory -File | Sort-Object Name | ForEach-Object {
        $_.Name + ':' + (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash
    }) -join ','
    $reusePipe = '\\.\pipe\packclient-1rcp-test-' + [Guid]::NewGuid().ToString('N')
    $reuseArgs = '-NoProfile -NonInteractive -File "{0}" -PipeName "{1}" -EvidenceRoot "{2}" -RunId test-run -ConnectTimeoutMs 300 -IoTimeoutMs 300' -f
        $PeerScript, $reusePipe, (Split-Path -Parent $happy1.Directory)
    $reusePeer = Start-HiddenPowerShell $reuseArgs
    try { Assert-Equal (Wait-Checked $reusePeer 5000 'existing-output check') 1 'existing-output rejection exit' } finally { $reusePeer.Dispose() }
    $after = @(Get-ChildItem -LiteralPath $happy1.Directory -File | Sort-Object Name | ForEach-Object {
        $_.Name + ':' + (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash
    }) -join ','
    Assert-Equal $after $before 'all previous output filenames and bytes remain intact'
    Pass 'existing-output directory preserved'

    Write-Output "RESULT: $script:Passed tests passed"
} catch {
    $failure = $_
    Write-Output 'Synthetic process diagnostics:'
    Get-ChildItem -LiteralPath $TestRoot -File -Recurse | Where-Object {
        $_.Name -eq 'run-summary.txt' -or $_.Name.EndsWith('.stderr.txt')
    } | ForEach-Object {
        if ($_.Length -gt 0) {
            Write-Output $_.FullName
            Get-Content -LiteralPath $_.FullName | Select-Object -Last 20
        }
    }
    throw $failure
} finally {
    if ($KeepArtifacts) {
        Write-Output "artifacts=$TestRoot"
    } else {
        $resolvedTestRoot = [IO.Path]::GetFullPath($TestRoot)
        if ((Split-Path -Parent $resolvedTestRoot) -eq $TestParent.TrimEnd('\') -and
            (Split-Path -Leaf $resolvedTestRoot).StartsWith('packclient-screenshot-ipc-tests-', [StringComparison]::Ordinal)) {
            Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
