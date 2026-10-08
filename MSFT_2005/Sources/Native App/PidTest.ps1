using namespace System
using namespace System.Diagnostics
using namespace System.Management.Automation
using namespace System.Runtime.InteropServices

# ============================================================================
#  MS baseline: run the GENUINE Microsoft pidgenx.dll on the same key/config,
#  timed the same way as the PkeyLib script, so the two numbers are comparable.
#
#  It drives the internal validator directly (same chain the real dispatcher
#  uses), group UNKNOWN -> the DLL's own 20-group threaded scan, i.e. the exact
#  apples-to-apples of VerifyBinaryKey(..., targetGroupId = 0).
#
#    sub_180015270  create config object
#    sub_18000C970  load pkeyconfig.xrm-ms        (done ONCE, outside the timer)
#    sub_180009338  dispatcher / validate + scan  (THIS is what gets timed)
#
#  Offsets are for pidgenx.dll 10.0.26040.1000 (x64). If your build differs,
#  only the four RVAs below need changing.
# ============================================================================

Clear-Host
Set-Location $PSScriptRoot
[Environment]::CurrentDirectory = $PSScriptRoot

# Match the PkeyLib script's scheduling so the comparison is fair.
try {
    [Process]::GetCurrentProcess().PriorityClass = [ProcessPriorityClass]::High
    [Threading.Thread]::CurrentThread.Priority   = [Threading.ThreadPriority]::Highest
} catch { }

# ---- config -----------------------------------------------------------------
$CdKey   = "RHTBY-VWY6D-QJRJ9-JGQ3X-Q2289"
$Config  = Join-Path $PSScriptRoot "pkeyconfig.xrm-ms"
$DllName = "pidgenx.dll"
$DllPath = Join-Path $PSScriptRoot $DllName

# RVAs (pidgenx.dll 10.0.26040.1000 x64)
$RVA_CreateCfg  = 0x180015270
$RVA_LoadConfig = 0x18000C970
$RVA_Dispatch   = 0x180009338

if (-not (Test-Path $DllPath))  { throw "DLL not found: $DllPath" }
if (-not (Test-Path $Config))   { throw "Config not found: $Config" }

# ---- native glue (self-contained; no external module) -----------------------
if (!([PSTypeName]'PNative').Type) {
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class PNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibraryW(string lpFileName);

    // create config object:  int f(IntPtr outObj, IntPtr zero)
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int D_Create(IntPtr outObj, IntPtr zero);

    // load pkeyconfig:        int f(long cfgObj, IntPtr wpathCfg, long z1, long z2)
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int D_Load(long cfgObj, IntPtr wpathCfg, long z1, long z2);

    // dispatcher/validate:    int f(long cfgObjPlus10, long z1, IntPtr wKey, long z2,z3,z4,z5, IntPtr outObj)
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int D_Dispatch(long cfgObjPlus10, long z1, IntPtr wKey,
                                   long z2, long z3, long z4, long z5, IntPtr outObj);

    public static IntPtr Addr(IntPtr hModule, long rva) {
        long off = rva >= 0x180000000 ? rva - 0x180000000 : rva;   // preferred base -> actual
        return new IntPtr(hModule.ToInt64() + off);
    }
}
"@
}

# ---- load DLL and resolve the three functions -------------------------------
$h = [PNative]::LoadLibraryW($DllPath)
if ($h -eq [IntPtr]::Zero) { throw "LoadLibrary failed for $DllPath (err $([Marshal]::GetLastWin32Error()))" }

$fCreate   = [Marshal]::GetDelegateForFunctionPointer([PNative]::Addr($h, $RVA_CreateCfg),  [PNative+D_Create])
$fLoad     = [Marshal]::GetDelegateForFunctionPointer([PNative]::Addr($h, $RVA_LoadConfig), [PNative+D_Load])
$fDispatch = [Marshal]::GetDelegateForFunctionPointer([PNative]::Addr($h, $RVA_Dispatch),  [PNative+D_Dispatch])

# ---- build the config object + load pkeyconfig (NOT timed) ------------------
Write-Host "Loading configuration rules (pidgenx)..." -ForegroundColor Cyan
$tmp = [Marshal]::AllocHGlobal(8); [Marshal]::WriteInt64($tmp, 0)
[void]$fCreate.Invoke($tmp, [IntPtr]::Zero)
$cfgObj = [Marshal]::ReadIntPtr($tmp)
[Marshal]::FreeHGlobal($tmp)
if ([long]$cfgObj -eq 0) { throw "create-config returned null" }

$cfgPathPtr = [Marshal]::StringToHGlobalUni($Config)   # keep alive across the Load call
$hrLoad = $fLoad.Invoke($cfgObj.ToInt64(), $cfgPathPtr, 0L, 0L)
[Marshal]::FreeHGlobal($cfgPathPtr)
Write-Host ("Config load HRESULT: 0x{0:X}" -f $hrLoad)

# ---- the validation call (group unknown -> 20-group threaded scan) ----------
$keyPtr = [Marshal]::StringToHGlobalUni($CdKey)
$outObj = [Marshal]::AllocHGlobal(8); [Marshal]::WriteInt64($outObj, 0)

$timer = [Stopwatch]::StartNew()
$hr = $fDispatch.Invoke(($cfgObj.ToInt64() + 0x10), 0L, $keyPtr, 0L, 0L, 0L, 0L, $outObj)
$timer.Stop()

$heap = [Marshal]::ReadIntPtr($outObj)
[Marshal]::FreeHGlobal($outObj)
[Marshal]::FreeHGlobal($keyPtr)

if ($hr -ne 0 -or [long]$heap -le 0) {
    Write-Host ("`n[ X ] pidgenx returned 0x{0:X8}" -f $hr) -ForegroundColor DarkGray
    [String]::Format("DLL call took {0:N3} s ({1} ms)", $timer.Elapsed.TotalSeconds, $timer.ElapsedMilliseconds)
    return
}

# ---- decode the result struct (same offsets as Msft2005-Info.ps1) -----------
$serial   = [Marshal]::ReadInt32($heap, 0x18)          # full serial
$group    = [Marshal]::ReadByte($heap, 0x38)          # group id
$auth     = [Marshal]::ReadInt64($heap, 0x48)          # security / auth value
$flags    = [Marshal]::ReadInt32($heap, 0x44)
$upgrade  = $flags -band 0x1
$strPtr   = [Marshal]::ReadIntPtr($heap, 8)
$actStr   = if ($strPtr -ne [IntPtr]::Zero) { [Marshal]::PtrToStringUni($strPtr) } else { "NULL" }

[pscustomobject]@{
    Engine    = "Microsoft pidgenx.dll"
    Upgrade   = $upgrade
    Serial    = $serial
    Auth      = $auth
    Group     = $group
    ActString = $actStr
} | Format-List

[String]::Format("DLL call took {0:N3} s ({1} ms)", $timer.Elapsed.TotalSeconds, $timer.ElapsedMilliseconds)

# ---- notes ------------------------------------------------------------------
# * Timer wraps ONLY the validate/scan (sub_180009338), with pkeyconfig already
#   loaded -- the same unit of compute as PkeyLib's VerifyBinaryKey. PkeyLib's
#   timer also parses the XML inside the call, but that parse is ~1 ms vs the
#   ~300 ms scan, so it doesn't move the comparison. If you want a parse-
#   inclusive MS number, move $timer.Start() to just before $fLoad.Invoke.
# * Run BOTH scripts 5x and compare the MEDIAN (single runs swing ~20%).
# * Same CdKey + same pkeyconfig.xrm-ms in both -> identical work, fair race.
