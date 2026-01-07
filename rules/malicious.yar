/*
    Steam Mod 行为审计规则库 v2.0
    策略：区分 "敏感权限" (Yellow) 和 "恶意行为" (Red)
*/

// ==========================================
// 🔴 红色区域：几乎可以确定的恶意/高危行为
// ==========================================

rule Critical_Credential_Theft {
    meta:
        description = "【高危】试图读取 Steam 敏感凭证 (可能盗号)"
        severity = "Critical"
        category = "Security"
    strings:
        // ssfn 是 Steam 的授权文件，普通 Mod 绝无理由读取它
        $s1 = "ssfn" nocase
        $s2 = "loginusers.vdf" nocase
        $s3 = "config/config.vdf" nocase
        $s4 = "steam.exe" nocase
    condition:
        any of them
}

rule Critical_Obfuscation {
    meta:
        description = "【高危】代码经过严重混淆 (试图隐藏逻辑)"
        severity = "Critical"
        category = "Security"
    strings:
        // 匹配大量 Base64 加上执行函数，正常 Mod 代码不需要这样藏着掖着
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
        $eval = "eval(" 
        $exec = "exec("
        $compile = "compile("
    condition:
        ($eval or $exec or $compile) and $b64
}

rule Critical_DotNet_Obfuscation {
    meta:
        description = "【高危】检测到 .NET 混淆器特征"
        severity = "High"
        category = "Obfuscation"
    strings:
        // 常见 .NET 混淆器特征
        $confuser = "ConfuserEx" nocase
        $dotfuscator = "Dotfuscator" nocase
        $eazfuscator = "Eazfuscator" nocase
        $smartassembly = "SmartAssembly" nocase
        $obfuscar = "Obfuscar" nocase
        $agile = "Agile.NET" nocase
        $babel = "Babel Obfuscator" nocase
        $crypto = "Crypto Obfuscator" nocase
        // 混淆后的特征模式
        $invalid_names = /[\x00-\x1F\x7F-\xFF]{3,}/  // 非法字符作为名称
        $unicode_names = /[\u0400-\u04FF\u0600-\u06FF]{5,}/  // 西里尔/阿拉伯字符名称
    condition:
        any of ($confuser, $dotfuscator, $eazfuscator, $smartassembly, $obfuscar, $agile, $babel, $crypto) or
        (#invalid_names > 10) or (#unicode_names > 5)
}

rule Suspicious_Encrypted_Payload {
    meta:
        description = "【可疑】包含加密/编码的有效载荷"
        severity = "High"
        category = "Obfuscation"
    strings:
        // 常见的编码/加密函数组合
        $frombase64 = "FromBase64String" nocase
        $convert = "Convert.FromBase64" nocase
        $decompress = "DeflateStream" nocase
        $gzip = "GZipStream" nocase
        $aes = "AesManaged" nocase
        $rijndael = "RijndaelManaged" nocase
        $des = "DESCryptoServiceProvider" nocase
        $rc4 = "RC4" nocase
        // 动态加载
        $assembly_load = "Assembly.Load" nocase
        $invoke = "DynamicInvoke" nocase
        $reflection = "MethodInfo.Invoke" nocase
    condition:
        ($frombase64 or $convert) and ($assembly_load or $invoke or $reflection) or
        (($decompress or $gzip) and ($assembly_load or $invoke)) or
        (($aes or $rijndael or $des) and ($assembly_load or $invoke))
}

rule Suspicious_String_Obfuscation {
    meta:
        description = "【可疑】字符串混淆技术"
        severity = "Medium"
        category = "Obfuscation"
    strings:
        // 字符数组拼接（常见混淆手法）
        $char_array = /new\s+char\s*\[\s*\]\s*\{[^}]{50,}\}/
        // XOR 解密模式
        $xor_pattern = /\^\s*0x[0-9A-Fa-f]{1,2}/
        // 字符串反转
        $reverse = "Reverse(" nocase
        $chararray = "ToCharArray" nocase
    condition:
        $char_array or (#xor_pattern > 5) or ($reverse and $chararray)
}

rule Critical_Destructive_Commands {
    meta:
        description = "【高危】试图删除系统文件或格式化"
        severity = "Critical"
        category = "Security"
    strings:
        $rm_sys1 = "del C:\\Windows" nocase
        $rm_sys2 = "rm -rf /" 
        $rm_sys3 = "format c:" nocase
    condition:
        any of them
}

// ==========================================
// 🟡 黄色区域：敏感权限 (功能性检测)
// ==========================================

rule Sensitive_Privacy_Access {
    meta:
        description = "【敏感】读取玩家身份信息 (SteamID/用户名)"
        severity = "Sensitive"
        category = "Privacy"
    strings:
        // 这里列出 Godot/Python/Lua 中常见的获取用户信息的函数名
        $id1 = "GetSteamID" nocase
        $id2 = "GetPersonaName" nocase
        $id3 = "ISteamUser" nocase
        $id4 = "user_id" nocase
        $id5 = "player_name" nocase
    condition:
        any of them
}

rule Sensitive_Network_Access {
    meta:
        description = "【敏感】具备联网能力 (可能用于更新或上传数据)"
        severity = "Sensitive"
        category = "Network"
    strings:
        $net1 = "http://" nocase
        $net2 = "https://" nocase
        $net3 = "socket" nocase
        $net4 = "HTTPRequest" nocase // Godot 常用
    condition:
        // 排除掉上面定义的高危规则，避免重复报警
        any of them and not Critical_Credential_Theft
}

rule Sensitive_File_Write {
    meta:
        description = "【敏感】具备文件读写权限 (可能修改存档或配置)"
        severity = "Sensitive"
        category = "FileSystem"
    strings:
        $io1 = "File.new()" // Godot
        $io2 = "open("
        $io3 = "Directory.new()"
        $io4 = "os.remove" // 虽然是删除，但 Mod 管理器可能会用到
        $io5 = "shutil"
    condition:
        any of them and not Critical_Destructive_Commands
}