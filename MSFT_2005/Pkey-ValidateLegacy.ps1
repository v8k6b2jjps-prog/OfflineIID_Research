# ---------------------------------------------------------------------------
# Legacy_Validator.ps1  (single file: script + embedded validator)
#
# Validates legacy (BINK1998 / BINK2002) product keys without pidgenx.dll.
#   msft:rm/algorithm/pkey/980        -> Pid1998
#   msft:rm/algorithm/pkey/985 / 986  -> Pid2002
#
# The validator is pkeyLegacy.cs (minified) -> GZip -> Base64, unpacked and
# compiled with Add-Type at start-up. PowerShell 5.1 and 7, any CPU.
#
# Test keys:
#   980 : B2Y39-43MG6-MMGRG-7VKCF-VXMCM   -> Group 44,  Ch 366, Seq 659088
#   986 : VCFQD-V9FX9-46WVH-K3CD4-4J3JM   -> Group 100, Ch 652, Seq 828461
# ---------------------------------------------------------------------------

param(
    [string]$CdKey      = 'B2Y39-43MG6-MMGRG-7VKCF-VXMCM',
    [string]$LicenseXml = '.\PKeyConfigs\Legacy_License.xml',
    [switch]$AllBinks,        # check every BINK (default: stop at first match)
    [int]$Threads = 0         # 0 = one per CPU core, 1 = serial
)

Set-Location $PSScriptRoot
[Environment]::CurrentDirectory = $PSScriptRoot

#region Load validator (GZip + Base64 C# source)
if (-not ('PidKeyPlugIn.PKeyLegacyValidator' -as [type])) {
    $packed = @'
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
7UKMvzsrOwUcpYAraTv8/781DEl92T0AAA==
'@ -replace '\s'

    $ms = [IO.MemoryStream]::new([Convert]::FromBase64String($packed))
    $gz = [IO.Compression.GZipStream]::new($ms, [IO.Compression.CompressionMode]::Decompress)
    $sr = [IO.StreamReader]::new($gz, [Text.Encoding]::UTF8)
    try { $src = $sr.ReadToEnd() } finally { $sr.Dispose() }

    $at = @{ TypeDefinition = $src; Language = 'CSharp'; ErrorAction = 'Stop' }
    if ($PSVersionTable.PSEdition -ne 'Core') { $at.ReferencedAssemblies = 'System.Numerics' }   # PS 5.1 only
    Add-Type @at
}
#endregion

$V   = [PidKeyPlugIn.PKeyLegacyValidator]
$raw = $V::DecodeProductKey($CdKey)
if ($null -eq $raw) { throw "Not a valid 25-character legacy key: $CdKey" }

[xml]$xml = Get-Content -Path (Join-Path $PSScriptRoot $LicenseXml)
$pks    = @($xml.ProductKeyConfiguration.PublicKeys.PublicKey)
$groups = [string[]]@($pks | ForEach-Object { [string]$_.GroupId })
$algs   = [string[]]@($pks | ForEach-Object { [string]$_.AlgorithmId })
$binks  = [object[]]@($pks | ForEach-Object { [string]$_.PublicKeyValue })   # Base64, decoded in C#

Write-Host ("Key    : {0}" -f $CdKey)
Write-Host ("BINKs  : {0}   threads: {1}   mode: {2}`n" -f $pks.Count,
    $(if ($Threads -gt 0) { $Threads } else { [Environment]::ProcessorCount }),
    $(if ($AllBinks) { 'all matches' } else { 'first match' }))

# bool VerifyAll(raw, groups, algorithmIds, binks, allMatches, maxThreads, out LegacyKeyResult[] matches)
$hits = $null
$sw   = [Diagnostics.Stopwatch]::StartNew()
$ok   = $V::VerifyAll($raw, $groups, $algs, $binks, [bool]$AllBinks, $Threads, [ref]$hits)
$sw.Stop()

if ($ok) {
    foreach ($r in $hits) {
        Write-Host '=== Legacy key result ===' -ForegroundColor Green
        Write-Host ('Group        : {0}' -f $r.GroupId)
        Write-Host ('Algorithm    : {0}' -f $r.AlgorithmId)
        Write-Host ('Layout       : {0}  (BINK date {1})' -f $r.Layout, $r.BinkDate)
        Write-Host ('Upgrade Flag : {0}' -f $r.Upgrade)
        Write-Host ('Channel      : {0:D3}' -f $r.Channel)
        Write-Host ('Sequence     : {0:D6}' -f $r.Sequence)
        Write-Host ('Hash / Sig   : 0x{0:X8} / 0x{1:X16}' -f $r.Hash, $r.Signature)
        Write-Host ('Auth / Pid   : 0x{0:X8} / 0x{1:X8}' -f $r.AuthInfo, $r.PidValue)
        Write-Host ('Check time   : {0:N1} ms' -f $r.ElapsedMs)
        Write-Host
    }
} else {
    Write-Host 'No BINK accepted this key.' -ForegroundColor Yellow
}

Write-Host ("Result : {0}   matches: {1}   total: {2:N0} ms" -f $ok, $hits.Count, $sw.Elapsed.TotalMilliseconds)
