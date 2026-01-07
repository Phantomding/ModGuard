/*
    破坏性行为检测规则
*/

rule Destructive_System_Files {
    meta:
        description = "【严重】试图删除/修改系统文件"
        severity = "critical"
        category = "系统破坏"
    strings:
        // Windows
        $win1 = "del C:\\Windows" nocase
        $win2 = "rmdir /s C:\\Windows" nocase
        $win3 = "rd /s /q C:\\" nocase
        $win4 = "format c:" nocase
        $win5 = "deltree" nocase
        // Linux
        $linux1 = "rm -rf /" 
        $linux2 = "rm -rf /*"
        $linux3 = "dd if=/dev/zero"
        $linux4 = "> /dev/sda"
    condition:
        any of them
}

rule Destructive_MBR_Attack {
    meta:
        description = "【严重】可能破坏 MBR/引导扇区"
        severity = "critical"
        category = "系统破坏"
    strings:
        $mbr1 = "PhysicalDrive0" nocase
        $mbr2 = "\\\\.\\PhysicalDrive" nocase
        $mbr3 = "\\Device\\Harddisk" nocase
        $mbr4 = "0x7C00" // MBR 加载地址
    condition:
        any of them
}

rule Destructive_Ransomware_Pattern {
    meta:
        description = "【严重】疑似勒索软件行为"
        severity = "critical"
        category = "勒索软件"
    strings:
        // 文件加密
        $enc1 = "CryptEncrypt" nocase
        $enc2 = "CryptoStream" nocase
        $enc3 = "AesCryptoServiceProvider" nocase
        // 文件遍历 + 加密
        $walk1 = "Directory.GetFiles" nocase
        $walk2 = "os.walk" nocase
        $walk3 = "FindFirstFile" nocase
        // 勒索信息
        $ransom1 = "bitcoin" nocase
        $ransom2 = "ransom" nocase
        $ransom3 = "decrypt" nocase
        $ransom4 = "pay" nocase
        // 扩展名
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypto" nocase
    condition:
        (any of ($enc*)) and (any of ($walk*)) and (any of ($ransom*, $ext*))
}

rule Destructive_Wiper {
    meta:
        description = "【严重】数据擦除器特征"
        severity = "critical"
        category = "数据破坏"
    strings:
        $wipe1 = "SDelete" nocase
        $wipe2 = "cipher /w" nocase
        $wipe3 = "shred" nocase
        $wipe4 = "secure-delete" nocase
        // 覆盖模式
        $overwrite1 = /write.*0x00/ nocase
        $overwrite2 = /fill.*zero/ nocase
    condition:
        any of them
}

rule Destructive_Registry_Damage {
    meta:
        description = "【严重】破坏系统注册表"
        severity = "critical"
        category = "系统破坏"
    strings:
        $reg1 = "reg delete HKLM" nocase
        $reg2 = "reg delete HKCU" nocase
        $reg3 = "RegDeleteKey" nocase
        $reg4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
    condition:
        any of ($reg1, $reg2, $reg3)
}

rule Destructive_Service_Disable {
    meta:
        description = "【高危】禁用系统服务"
        severity = "high"
        category = "防御规避"
    strings:
        $svc1 = "net stop" nocase
        $svc2 = "sc stop" nocase
        $svc3 = "sc delete" nocase
        $svc4 = "taskkill /f" nocase
        // 目标服务
        $target1 = "WinDefend" nocase
        $target2 = "MsMpEng" nocase
        $target3 = "SecurityHealth" nocase
        $target4 = "wscsvc" nocase
    condition:
        any of ($svc*) and any of ($target*)
}

rule Destructive_Shadow_Delete {
    meta:
        description = "【严重】删除系统还原点/卷影副本"
        severity = "critical"
        category = "备份破坏"
    strings:
        $shadow1 = "vssadmin delete shadows" nocase
        $shadow2 = "wmic shadowcopy delete" nocase
        $shadow3 = "bcdedit /set" nocase
        $shadow4 = "recoveryenabled No" nocase
    condition:
        any of them
}
