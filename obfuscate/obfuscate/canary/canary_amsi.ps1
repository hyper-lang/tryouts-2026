# canary_amsi.ps1 - self-contained lab canary harness (R6 baseline/patched AMSI + ETW)
#
# The ONLY measurer of R6 baseline/patched AMSI/ETW suppression.  Runs on a
# deploy-host-condition machine (Windows PowerShell 5.1 + Defender only, no
# Python/toolchain) and emits a single JSON document to stdout whose keys match
# obfuscate/verify.py CANARY_RECORD_KEYS.
#
# Usage (see obfuscate/canary/README.md for the full procedure):
#   powershell -NoProfile -ExecutionPolicy Bypass -File canary_amsi.ps1 `
#       -BaselinePath baseline_patched_off.exe -PatchedPath patched.exe `
#       -Marker 'Invoke-Mimikatz' [-NoETW] [-WaitSeconds 6]
#
# Exit codes: 0 = the harness completed its measurements and emitted a JSON
# document (status records the verdict); non-zero = a harness failure (missing
# artifact, bad parameters, probe core failed to compile, an artifact could not
# be started).  Every claim in the JSON is version-scoped ("measured on the lab
# run with <versions>"), never an unverifiable evasion claim.
#
# Measurement model (documented boundary, honest evidence only):
#   * AMSI marker -> the AMSI test call path (AmsiInitialize/AmsiScanBuffer) is
#     exercised in the harness process.  On an unpatched context the marker is
#     flagged; on a context where in-process AMSI is suppressed
#     (AmsiScanBuffer returns E_INVALIDARG 0x80070057, the patch contract) the
#     scan reports clean.  Which context the harness runs in is recorded
#     (self probe) so the marker result is interpreted honestly.
#   * Artifact suppression -> each artifact is started and, while running, its
#     process image is probed read-only: AmsiScanBuffer (amsi.dll) and, unless
#     -NoETW, EtwEventWrite (ntdll.dll) byte sequences are compared against the
#     unpatched on-disk images.  A differing first byte 0xEB (the canonical
#     relative-jump NOP-sled prefix of every seed variant) records the artifact
#     as suppressed.  This is the baseline(control)/patched cross-process
#     measurement.

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $BaselinePath,

    [Parameter(Mandatory = $true, Position = 1)]
    [string] $PatchedPath,

    # Benign, Defender/AMSI-signatured content marker, calibrated in the team's
    # lab.  A real detect on the baseline is the point of the canary; tune this
    # until a fresh unpatched PowerShell reports it flagged (see the README).
    [string] $Marker = 'Invoke-Mimikatz',

    # Skip the optional ETW canary (process-level EtwEventWrite suppression).
    [switch] $NoETW,

    # Seconds each artifact is allowed to reach its patched state before the
    # cross-process probe; also the sample window within which it is alive.
    [int] $WaitSeconds = 6,

    # Extra process arguments forwarded to the artifacts (default: none, the
    # lab artifacts run standalone).  Kept for hermetic tests and custom labs.
    [string[]] $Arguments = @()
)

$ErrorActionPreference = 'Stop'

function Write-Stderr {
    param([string] $Message)
    [Console]::Error.WriteLine($Message)
}

# ---------------------------------------------------------------------------
# Probe core (single Add-Type; .NET Framework-compatible C#).
# ---------------------------------------------------------------------------
$probeSource = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ObfCanary
{
    public static class AmsiProbe
    {
        // ---- AMSI test call path: the public, documented AMSI API, used only
        // ---- to scan a configurable benign marker string on the lab image.
        [DllImport("amsi.dll", ExactSpelling = true)]
        private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);
        [DllImport("amsi.dll", ExactSpelling = true)]
        private static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);
        [DllImport("amsi.dll", ExactSpelling = true)]
        private static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length,
            string contentName, IntPtr session, out int result);
        [DllImport("amsi.dll", ExactSpelling = true)]
        private static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);
        [DllImport("amsi.dll", ExactSpelling = true)]
        private static extern void AmsiUninitialize(IntPtr amsiContext);

        public const int AMSI_RESULT_BLOCK_BY_ADMIN_START = 16384;
        public const int AMSI_RESULT_DETECTED = 32768;

        // Returns the AmsiScanBuffer HRESULT; amsiResult receives the
        // AMSI_RESULT scan verdict.  In a process with in-process AMSI
        // suppression applied, AmsiScanBuffer returns E_INVALIDARG (0x80070057)
        // = the aborted, non-significant ("clean") contract.
        public static int Scan(string contentName, byte[] buffer, out int amsiResult)
        {
            amsiResult = -1;
            IntPtr ctx = IntPtr.Zero;
            IntPtr session = IntPtr.Zero;
            int hresult = AmsiInitialize(contentName, out ctx);
            if (hresult != 0) { return hresult; }
            try
            {
                hresult = AmsiOpenSession(ctx, out session);
                if (hresult != 0) { return hresult; }
                return AmsiScanBuffer(ctx, buffer, (uint)buffer.Length, contentName, session, out amsiResult);
            }
            finally
            {
                if (session != IntPtr.Zero) { AmsiCloseSession(ctx, session); }
                if (ctx != IntPtr.Zero) { AmsiUninitialize(ctx); }
            }
        }

        // ---- ETW test path: the minimal consumer call through ntdll's
        // ---- EtwEventWrite.  A suppressed (patched) ntdll returns
        // ---- STATUS_SUCCESS (0); the live write path rejects the zeroed
        // ---- descriptor with a failure status.
        [DllImport("ntdll.dll", ExactSpelling = true)]
        private static extern int EtwEventWrite(IntPtr regHandle, IntPtr eventDescriptor,
            uint userDataCount, IntPtr userData);

        public static int TestEtwWrite()
        {
            return EtwEventWrite(IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero);
        }

        // ---- Cross-process patch-presence probe -----------------------------
        [StructLayout(LayoutKind.Sequential)]
        private struct ModuleInfo
        {
            public IntPtr BaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr process, out bool wow64);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer,
            UIntPtr size, out UIntPtr bytesRead);
        [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
        private static extern bool EnumProcessModulesEx(IntPtr process, IntPtr[] modules, uint cb,
            out uint needed, uint filterFlag);
        [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetModuleBaseName(IntPtr process, IntPtr module,
            StringBuilder name, uint size);
        [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
        private static extern bool GetModuleInformation(IntPtr process, IntPtr module,
            out ModuleInfo info, uint cb);

        private const uint ProcessQueryLimitedInfo = 0x1000;
        private const uint ProcessVmRead = 0x0010;
        private const uint ListModulesAll = 0x03;

        private class SectionEntry
        {
            public uint VirtualAddress;
            public uint VirtualSize;
            public uint RawSize;
            public uint RawPointer;
        }

        private class DiskImage
        {
            public byte[] ExportBytes;
            public long ExportRva;
            public uint SizeOfImage;
        }

        private static uint RvaToOffset(SectionEntry[] sections, uint rva)
        {
            for (int i = 0; i < sections.Length; i++)
            {
                uint start = sections[i].VirtualAddress;
                uint end = sections[i].VirtualAddress
                    + (sections[i].VirtualSize > sections[i].RawSize
                        ? sections[i].VirtualSize : sections[i].RawSize);
                if (rva >= start && rva < end)
                {
                    return rva - start + sections[i].RawPointer;
                }
            }
            return 0xFFFFFFFF;
        }

        private static string ReadCString(byte[] data, int offset, int max)
        {
            int end = offset;
            while (end < data.Length && end < offset + max && data[end] != 0)
            {
                end++;
            }
            return Encoding.ASCII.GetString(data, offset, end - offset);
        }

        // Reads the on-disk, unpatched export bytes (plus RVA and image size)
        // straight from the DLL file -- the independent reference for the
        // cross-process comparison.  Returns null when the DLL or export cannot
        // be parsed.
        private static DiskImage ReadDisk(string dllPath, string export, int count)
        {
            if (!File.Exists(dllPath)) { return null; }
            byte[] file;
            try { file = File.ReadAllBytes(dllPath); }
            catch { return null; }
            if (file.Length < 0x40) { return null; }
            uint peOff = (uint)BitConverter.ToInt32(file, 0x3C);
            if (peOff + 24 > (uint)file.Length) { return null; }
            if (BitConverter.ToUInt32(file, (int)peOff) != 0x4550) { return null; }
            ushort magic = BitConverter.ToUInt16(file, (int)peOff + 24);
            if (magic != 0x10B && magic != 0x20B) { return null; }
            ushort numSections = BitConverter.ToUInt16(file, (int)peOff + 6);
            ushort optSize = BitConverter.ToUInt16(file, (int)peOff + 20);
            int sectionTable = (int)peOff + 24 + optSize;
            if (sectionTable + numSections * 40 > file.Length) { return null; }
            SectionEntry[] sections = new SectionEntry[numSections];
            for (int i = 0; i < numSections; i++)
            {
                int p = sectionTable + i * 40;
                SectionEntry se = new SectionEntry();
                se.VirtualSize = BitConverter.ToUInt32(file, p + 8);
                se.VirtualAddress = BitConverter.ToUInt32(file, p + 12);
                se.RawSize = BitConverter.ToUInt32(file, p + 16);
                se.RawPointer = BitConverter.ToUInt32(file, p + 20);
                sections[i] = se;
            }
            int ddOffset = (int)peOff + 24 + (magic == 0x20B ? 112 : 96);
            uint exportRva = BitConverter.ToUInt32(file, ddOffset);
            uint exportFileOff = RvaToOffset(sections, exportRva);
            if (exportFileOff == 0xFFFFFFFF || exportFileOff + 40 > (uint)file.Length) { return null; }
            uint imageSize = BitConverter.ToUInt32(file, (int)peOff + 24 + (magic == 0x20B ? 56 : 52));
            int nNames = BitConverter.ToInt32(file, (int)exportFileOff + 24);
            uint addrTableRva = BitConverter.ToUInt32(file, (int)exportFileOff + 28);
            uint nameTableRva = BitConverter.ToUInt32(file, (int)exportFileOff + 32);
            uint ordinalTableRva = BitConverter.ToUInt32(file, (int)exportFileOff + 36);
            uint nameTableOff = RvaToOffset(sections, nameTableRva);
            uint addrTableOff = RvaToOffset(sections, addrTableRva);
            uint ordinalTableOff = RvaToOffset(sections, ordinalTableRva);
            if (nameTableOff == 0xFFFFFFFF || addrTableOff == 0xFFFFFFFF || ordinalTableOff == 0xFFFFFFFF)
            {
                return null;
            }
            for (int i = 0; i < nNames; i++)
            {
                uint nameRva = BitConverter.ToUInt32(file, (int)nameTableOff + i * 4);
                uint nameOff = RvaToOffset(sections, nameRva);
                if (nameOff == 0xFFFFFFFF) { continue; }
                string name = ReadCString(file, (int)nameOff, 64);
                if (string.Equals(name, export, StringComparison.Ordinal))
                {
                    ushort ord = BitConverter.ToUInt16(file, (int)ordinalTableOff + i * 2);
                    uint funcRva = BitConverter.ToUInt32(file, (int)addrTableOff + ord * 4);
                    uint funcOff = RvaToOffset(sections, funcRva);
                    if (funcOff == 0xFFFFFFFF) { return null; }
                    int available = (int)(file.Length - funcOff);
                    if (available < count) { count = available; }
                    byte[] bytes = new byte[count];
                    Array.Copy(file, (int)funcOff, bytes, 0, count);
                    DiskImage image = new DiskImage();
                    image.ExportBytes = bytes;
                    image.ExportRva = (long)funcRva;
                    image.SizeOfImage = imageSize;
                    return image;
                }
            }
            return null;
        }

        private static byte[] ReadRemoteBytes(IntPtr process, IntPtr address, int count)
        {
            byte[] buffer = new byte[count];
            UIntPtr bytesRead;
            if (!ReadProcessMemory(process, address, buffer, new UIntPtr((uint)count), out bytesRead))
            {
                return null;
            }
            return bytesRead.ToUInt64() == (ulong)count ? buffer : null;
        }

        // 1 = suppressed (patched), 0 = present-but-unpatched,
        // -1 = not observed / not comparable (module absent, arch mismatch,
        //      different image version, or the read failed).
        public static int RemoteSuppressed(uint processId, string dll, string export)
        {
            IntPtr process = OpenProcess(ProcessQueryLimitedInfo | ProcessVmRead, false, processId);
            if (process == IntPtr.Zero) { return -1; }
            try
            {
                bool wow64;
                if (!IsWow64Process(process, out wow64)) { return -1; }
                string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                string systemDir = wow64 ? "SysWOW64" : "System32";
                string dllPath = Path.Combine(Path.Combine(windowsDir, systemDir), dll);
                DiskImage disk = ReadDisk(dllPath, export, 16);
                if (disk == null) { return -1; }

                IntPtr[] modules = new IntPtr[1024];
                uint needed = 0;
                if (!EnumProcessModulesEx(process, modules, (uint)(modules.Length * IntPtr.Size),
                    out needed, ListModulesAll))
                {
                    return -1;
                }
                int moduleCount = (int)(needed / (uint)IntPtr.Size);
                if (moduleCount > modules.Length) { moduleCount = modules.Length; }
                StringBuilder nameBuffer = new StringBuilder(64);
                for (int i = 0; i < moduleCount; i++)
                {
                    uint len = GetModuleBaseName(process, modules[i], nameBuffer, (uint)nameBuffer.Capacity);
                    if (len == 0 || !string.Equals(nameBuffer.ToString(), dll, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    ModuleInfo info;
                    if (!GetModuleInformation(process, modules[i], out info,
                        (uint)Marshal.SizeOf(typeof(ModuleInfo))))
                    {
                        return -1;
                    }
                    // Same image version expected on the lab box; a size mismatch
                    // means a different module and the compare is meaningless.
                    if (info.SizeOfImage != disk.SizeOfImage) { return -1; }
                    IntPtr remoteFunc = new IntPtr(info.BaseOfDll.ToInt64() + disk.ExportRva);
                    byte[] remote = ReadRemoteBytes(process, remoteFunc, disk.ExportBytes.Length);
                    if (remote == null) { return -1; }
                    bool differs = false;
                    for (int k = 0; k < disk.ExportBytes.Length; k++)
                    {
                        if (remote[k] != disk.ExportBytes[k]) { differs = true; break; }
                    }
                    if (!differs) { return 0; }
                    // Our patch vectors always begin with a relative-jump NOP
                    // sled (EB k).  A differing first byte that is not EB is not
                    // one of our vectors (e.g. a benign service update).
                    if (remote[0] == 0xEB) { return 1; }
                    return 0;
                }
                return -1;
            }
            finally
            {
                CloseHandle(process);
            }
        }
    }
}
'@

function Ensure-ProbeCore {
    try {
        $null = [ObfCanary.AmsiProbe]::AMSI_RESULT_DETECTED
    }
    catch {
        Add-Type -TypeDefinition $probeSource -ErrorAction Stop
    }
}

function Get-PlatformText {
    $osInfo = [System.Environment]::OSVersion
    return ('{0} (build {1}) ; PowerShell {2} ({3} edition) ; {4}-bit' -f `
        $osInfo.VersionString, $osInfo.Version, $PSVersionTable.PSVersion,
        $PSVersionTable.PSEdition, ([System.IntPtr]::Size * 8))
}

# .NET Framework Release DWORD; 0x82405 == 4.8 (same key verify reads).
function Get-NetFrameworkRelease {
    $keyPath = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
    try {
        if (Test-Path -LiteralPath $keyPath) {
            $item = Get-ItemProperty -LiteralPath $keyPath -ErrorAction Stop
            if ($null -ne $item.Release) { return [int]$item.Release }
        }
    }
    catch { }
    return $null
}

function Get-FrameworkVersionText {
    param([int] $Release)
    if ($null -eq $Release) { return 'unknown' }
    switch ($Release) {
        378389 { return '4.5' }
        378675 { return '4.5.1' }
        378758 { return '4.5.2' }
        379893 { return '4.6' }
        381029 { return '4.6.1' }
        381030 { return '4.6.1' }
        394254 { return '4.6.2' }
        394271 { return '4.7' }
        394802 { return '4.7.1' }
        394806 { return '4.7.1' }
        461308 { return '4.7.2' }
        461310 { return '4.7.2' }
        528040 { return '4.8' }
        528372 { return '4.8' }
        528449 { return '4.8.1' }
        533320 { return '4.8.1' }
        533325 { return '4.8.1' }
        default { return ('4.x (Release {0})' -f $Release) }
    }
}

function Get-DefenderStatus {
    $status = @{
        defender_mode = $null
        mengine_version = $null
        definition_am_versions = $null
    }
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        if ($null -ne $s) {
            $updated = $null
            try { $updated = $s.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm') }
            catch { }
            $status.defender_mode = ('AV enabled={0}; RTP enabled={1}; tamper protected={2}' -f `
                $s.AntivirusEnabled, $s.RealTimeProtectionEnabled, $s.IsTamperProtected)
            $status.mengine_version = [string]$s.AMEngineVersion
            $status.definition_am_versions = ('signature {0} (updated {1}); product {2}' -f `
                $s.AntivirusSignatureVersion, $updated, $s.AMProductVersion)
        }
    }
    catch {
        # Defender not present / module unavailable: fields stay null; the
        # --no-defender skip is the operator's call at the CLI, here we just
        # record honestly.
    }
    return $status
}

# Marker scan through the AMSI test call path, in the harness process.
# suppressed_scan is true when AmsiScanBuffer answered E_INVALIDARG (the
# in-process suppression contract) -- the effective clean outcome.
function Invoke-AmsiScan {
    param([string] $MarkerText, [string] $ContentName)
    $buffer = [System.Text.Encoding]::Unicode.GetBytes($MarkerText)
    $scanResult = -1
    $hresult = [ObfCanary.AmsiProbe]::Scan($ContentName, $buffer, [ref] $scanResult)
    $hresultU = [uint32]$hresult
    $suppressed = ($hresultU -eq 0x80070057)
    $flagged = ((-not $suppressed) -and ($hresultU -eq 0) -and ($scanResult -ge [ObfCanary.AmsiProbe]::AMSI_RESULT_BLOCK_BY_ADMIN_START))
    return @{
        flagged = [bool]$flagged
        suppressed_scan = [bool]$suppressed
        hresult = ('0x{0:X8}' -f $hresultU)
        amsi_result = [int]$scanResult
    }
}

function Invoke-EtwProbe {
    $value = [ObfCanary.AmsiProbe]::TestEtwWrite()
    $valueU = [uint32]$value
    return @{
        suppressed = ($valueU -eq 0)
        status_hex = ('0x{0:X8}' -f $valueU)
    }
}

function Convert-PatchState {
    param([int] $Code)
    if ($Code -eq 1) { return 'patched' }
    if ($Code -eq 0) { return 'unpatched' }
    return 'not_observed'
}

function Probe-Process {
    param([int] $ProcessId, [bool] $IncludeEtw)
    $amsiCode = [ObfCanary.AmsiProbe]::RemoteSuppressed([uint32]$ProcessId, 'amsi.dll', 'AmsiScanBuffer')
    $amsi = Convert-PatchState -Code $amsiCode
    $etw = $null
    if ($IncludeEtw) {
        $etwCode = [ObfCanary.AmsiProbe]::RemoteSuppressed([uint32]$ProcessId, 'ntdll.dll', 'EtwEventWrite')
        $etw = Convert-PatchState -Code $etwCode
    }
    return @{ amsi = $amsi; etw = $etw }
}

function Get-CanaryMode {
    param([string] $Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        $hostMarker = ($text.IndexOf('OBFUSCATE_HOST_V1', [System.StringComparison]::Ordinal) -ge 0)
        $patchMarker = ($text.IndexOf('OBFUSCATE_PATCH_V1', [System.StringComparison]::Ordinal) -ge 0)
        if ($hostMarker) {
            if ($patchMarker) { return 'B' }
            return 'B baseline'
        }
    }
    catch { }
    return 'unknown'
}

function Invoke-ArtifactProbe {
    param(
        [string] $ExePath,
        [string] $LegName,
        [string] $MarkerText,
        [bool] $IncludeEtw,
        [int] $WaitFor,
        [string[]] $ExtraArgs
    )
    $result = @{
        artifact = [string]$ExePath
        ran = [bool]$false
        alive = $null
        amsi = 'not_observed'
        etw = $null
        marker_flagged = $null
        marker_hresult = $null
        marker_amsi_result = $null
        note = $null
    }
    try {
        if ($ExtraArgs -and $ExtraArgs.Count -gt 0) {
            $proc = Start-Process -FilePath $ExePath -ArgumentList $ExtraArgs -PassThru -ErrorAction Stop
        }
        else {
            $proc = Start-Process -FilePath $ExePath -PassThru -ErrorAction Stop
        }
        $result.ran = $true
    }
    catch {
        $result.note = ('cannot start {0}: {1}' -f $ExePath, $_.Exception.Message)
        return $result
    }

    Start-Sleep -Seconds $WaitFor
    try { $proc.Refresh() }
    catch { }
    if ($proc.HasExited) {
        $result.alive = $false
        $result.note = ('process exited (code {0}) before the sample window; process-level suppression not taken as evidence' -f $proc.ExitCode)
        return $result
    }

    $result.alive = $true
    $scan = Invoke-AmsiScan -MarkerText $MarkerText -ContentName ('obfuscate-canary-' + $LegName)
    $result.marker_flagged = $scan.flagged
    $result.marker_hresult = $scan.hresult
    $result.marker_amsi_result = $scan.amsi_result

    $probe = Probe-Process -ProcessId $proc.Id -IncludeEtw $IncludeEtw
    $result.amsi = $probe.amsi
    $result.etw = $probe.etw

    try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    catch { }
    return $result
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$exitCode = 0
try {
    if ([string]::IsNullOrWhiteSpace($BaselinePath)) { throw 'baseline artifact path is required' }
    if ([string]::IsNullOrWhiteSpace($PatchedPath)) { throw 'patched artifact path is required' }
    if ([string]::IsNullOrWhiteSpace($Marker)) { throw 'marker must be a non-empty string' }
    if (-not (Test-Path -LiteralPath $BaselinePath -PathType Leaf)) { throw ('baseline artifact not found: {0}' -f $BaselinePath) }
    if (-not (Test-Path -LiteralPath $PatchedPath -PathType Leaf)) { throw ('patched artifact not found: {0}' -f $PatchedPath) }
    if ($WaitSeconds -lt 1) { throw 'wait-seconds must be >= 1' }

    # Record the R6 lab-image identity FIRST: platform build, .NET Framework
    # Release DWORD, Defender mode + engine/definition versions.
    $platformText = Get-PlatformText
    $release = Get-NetFrameworkRelease
    $frameworkText = Get-FrameworkVersionText -Release $release
    $defender = Get-DefenderStatus
    $canaryMode = Get-CanaryMode -Path $PatchedPath

    Ensure-ProbeCore

    # Harness context probe: which in-process AMSI state does the harness itself
    # run under?  Determines what the marker "should" do (flagged when unpatched,
    # clean when suppressed) and lets the verdict stay honest in both contexts.
    $selfProbe = Probe-Process -ProcessId $PID -IncludeEtw $true
    $selfSuppressed = ($selfProbe.amsi -eq 'patched')

    $baselineInfo = Invoke-ArtifactProbe -ExePath $BaselinePath -LegName 'baseline' `
        -MarkerText $Marker -IncludeEtw (-not $NoETW) -WaitFor $WaitSeconds -ExtraArgs $Arguments
    $patchedInfo = Invoke-ArtifactProbe -ExePath $PatchedPath -LegName 'patched' `
        -MarkerText $Marker -IncludeEtw (-not $NoETW) -WaitFor $WaitSeconds -ExtraArgs $Arguments

    if (-not $baselineInfo.ran) {
        throw ('baseline artifact could not be started: {0}' -f $baselineInfo.note)
    }
    if (-not $patchedInfo.ran) {
        throw ('patched artifact could not be started: {0}' -f $patchedInfo.note)
    }

    $observed = @('unpatched', 'patched')
    $baselineObserved = ($baselineInfo.alive -eq $true) -and ($observed -contains $baselineInfo.amsi)
    $patchedObserved = ($patchedInfo.alive -eq $true) -and ($observed -contains $patchedInfo.amsi)

    # Marker context consistency: in an unpatched harness context the marker must
    # be flagged (the marker calibration + Defender-on check); in a suppressed
    # context the AMSI test call path must report clean.  A null scan (artifact
    # exited before the sample window) means no judgment either way.
    if (($null -ne $baselineInfo.marker_flagged) -and ($null -ne $patchedInfo.marker_flagged)) {
        $expectedFlag = (-not $selfSuppressed)
        $markerConsistent = `
            ($baselineInfo.marker_flagged -eq $expectedFlag) -and
            ($patchedInfo.marker_flagged -eq $expectedFlag)
    }
    else {
        $markerConsistent = $null
    }

    $etwGate = -not $NoETW
    $etwOk = (-not $etwGate)
    if ($etwGate) {
        $etwOk = ($patchedInfo.etw -eq 'patched')
    }

    if ((-not $baselineObserved) -or (-not $patchedObserved)) {
        $status = 'unknown'
        $reason = ('not all expected process observations were made (an artifact exited before the sample window, or a cross-process probe was not comparable); ' +
            'baseline AmsiScanBuffer={0}, patched AmsiScanBuffer={1}' -f $baselineInfo.amsi, $patchedInfo.amsi)
    }
    elseif ($markerConsistent -eq $false) {
        $status = 'fail'
        $reason = ('marker calibration/context check failed: the harness process reports AMSI {0} (expected the marker {1} in that context), but the AMSI test call path reported baseline flagged={2}, patched flagged={3}; calibrate -Marker on an unpatched lab PowerShell' -f `
            $selfProbe.amsi, $(if ($selfSuppressed) { 'clean' } else { 'flagged' }),
            [bool]$baselineInfo.marker_flagged, [bool]$patchedInfo.marker_flagged)
    }
    elseif ($baselineInfo.amsi -ne 'unpatched') {
        $status = 'fail'
        $reason = ('baseline artifact did not confirm an unpatched AmsiScanBuffer (reported {0}); the control is violated' -f $baselineInfo.amsi)
    }
    elseif (($patchedInfo.amsi -ne 'patched') -or (-not $etwOk)) {
        $etwText = $(if ($etwGate) { ('EtwEventWrite={0}' -f $patchedInfo.etw) } else { 'ETW not measured (-NoETW)' })
        $status = 'fail'
        $reason = ('patched artifact did not confirm suppression: AmsiScanBuffer={0}; {1}' -f $patchedInfo.amsi, $etwText)
    }
    else {
        $etwText = $(if ($etwGate) { 'EtwEventWrite' } else { 'ETW skipped (-NoETW)' })
        $status = 'pass'
        $reason = ('baseline artifact confirmed unpatched (AmsiScanBuffer control); patched artifact confirmed suppressed for AmsiScanBuffer and {0}; marker behaved per context' -f $etwText)
    }

    $diff = @{
        baseline_marker_flagged = $baselineInfo.marker_flagged
        patched_marker_flagged = $patchedInfo.marker_flagged
        baseline_amsi_suppressed = $baselineInfo.amsi
        patched_amsi_suppressed = $patchedInfo.amsi
        baseline_etw_suppressed = $baselineInfo.etw
        patched_etw_suppressed = $patchedInfo.etw
        context = ('harness process AMSI {0}' -f $selfProbe.amsi)
        note = 'marker scan reflects the harness process context (standalone = unpatched; in-process within the patched agent = suppressed); artifact suppression is the cross-process read of the running artifact'
    }

    $detail = ("AMSI marker '{0}' via the AMSI test call path: baseline leg flagged={1}, patched leg flagged={2}; " +
        'baseline artifact AmsiScanBuffer={3}, patched artifact AmsiScanBuffer={4}; marker canary mode {5}. ' +
        "measured on the lab run with platform '{6}', .NET Framework Release {7} ({8}), Defender mode '{9}', " +
        'MpEngine {10}, definitions {11}.') -f `
        $Marker, [bool]$baselineInfo.marker_flagged, [bool]$patchedInfo.marker_flagged,
        $baselineInfo.amsi, $patchedInfo.amsi, $canaryMode,
        $platformText, $release, $frameworkText, $defender.defender_mode,
        $defender.mengine_version, $defender.definition_am_versions

    $record = @{
        mode = 'amshi'
        output = [string]$PatchedPath
        canary_mode = [string]$canaryMode
        status = [string]$status
        reason = [string]$reason
        platform = [string]$platformText
        net_framework_release = $release
        defender_mode = $defender.defender_mode
        mengine_version = $defender.mengine_version
        definition_am_versions = $defender.definition_am_versions
        baseline = $baselineInfo
        patched = $patchedInfo
        diff = $diff
        detail = [string]$detail
    }

    $json = $record | ConvertTo-Json -Depth 10 -Compress
    [Console]::Out.WriteLine($json)
}
catch {
    Write-Stderr ('obfuscate canary harness error: {0}' -f $_.Exception.Message)
    $exitCode = 1
}
exit $exitCode