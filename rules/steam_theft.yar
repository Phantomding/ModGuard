/*
    Steam 账号窃取检测规则
    专门针对 Steam 凭证盗取行为
*/

rule Steam_SSFN_Theft {
    meta:
        description = "【严重】试图访问 Steam 授权令牌文件 (SSFN)"
        severity = "critical"
        category = "凭证窃取"
        author = "ModGuard"
    strings:
        $ssfn1 = "ssfn" nocase
        $ssfn2 = /ssfn[0-9]+/ nocase
        // 常见的文件搜索模式
        $search1 = "*.ssfn" nocase
        $search2 = "ssfn*" nocase
    condition:
        any of them
}

rule Steam_LoginUsers_Access {
    meta:
        description = "【严重】试图读取 Steam 登录用户信息"
        severity = "critical"
        category = "凭证窃取"
    strings:
        $login1 = "loginusers.vdf" nocase
        $login2 = "config\\loginusers" nocase
        $login3 = "config/loginusers" nocase
    condition:
        any of them
}

rule Steam_Config_Theft {
    meta:
        description = "【高危】试图读取 Steam 配置文件"
        severity = "high"
        category = "凭证窃取"
    strings:
        $cfg1 = "config.vdf" nocase
        $cfg2 = "localconfig.vdf" nocase
        $cfg3 = "sharedconfig.vdf" nocase
    condition:
        any of them
}

rule Steam_Cookie_Session {
    meta:
        description = "【严重】试图获取 Steam 会话/Cookie"
        severity = "critical"
        category = "会话劫持"
    strings:
        $cookie1 = "steamLoginSecure" nocase
        $cookie2 = "sessionid" nocase
        $cookie3 = "steam_login" nocase
        $cookie4 = "steamRememberLogin" nocase
        // Cookie 存储路径
        $path1 = "htmlcache" nocase
        $path2 = "cookies" nocase
    condition:
        2 of them
}

rule Steam_API_Key_Search {
    meta:
        description = "【高危】试图搜索或提取 Steam API 密钥"
        severity = "high"
        category = "API滥用"
    strings:
        $key1 = "STEAM_API_KEY" nocase
        $key2 = "steam_api_key" nocase
        $key3 = "WebAPIKey" nocase
        $key4 = /[A-F0-9]{32}/ // Steam API Key 格式
    condition:
        any of ($key1, $key2, $key3) or (#key4 > 3)
}

rule Steam_Trade_Manipulation {
    meta:
        description = "【严重】可能操纵 Steam 交易"
        severity = "critical"
        category = "交易欺诈"
    strings:
        $trade1 = "GetTradeOffers" nocase
        $trade2 = "SendTradeOffer" nocase
        $trade3 = "AcceptTradeOffer" nocase
        $trade4 = "DeclineTradeOffer" nocase
        // 交易确认
        $conf1 = "GetConfirmations" nocase
        $conf2 = "AcceptConfirmation" nocase
    condition:
        2 of them
}

rule Steam_Wallet_Access {
    meta:
        description = "【严重】试图访问 Steam 钱包信息"
        severity = "critical"
        category = "资金窃取"
    strings:
        $wallet1 = "GetWalletBalance" nocase
        $wallet2 = "wallet_balance" nocase
        $wallet3 = "steam_wallet" nocase
        $wallet4 = "AddFunds" nocase
    condition:
        any of them
}

rule Steam_Guard_Bypass {
    meta:
        description = "【严重】试图绕过 Steam Guard"
        severity = "critical"
        category = "安全绕过"
    strings:
        $guard1 = "steamguard" nocase
        $guard2 = "twofactor" nocase
        $guard3 = "2fa" nocase
        $guard4 = "shared_secret" nocase
        $guard5 = "identity_secret" nocase
        // Mafile (SDA 格式)
        $mafile = ".maFile" nocase
    condition:
        2 of them
}

rule Steam_Registry_Query {
    meta:
        description = "【高危】读取 Steam 注册表信息"
        severity = "high"
        category = "信息收集"
    strings:
        $reg1 = "SOFTWARE\\Valve\\Steam" nocase
        $reg2 = "SOFTWARE\\WOW6432Node\\Valve\\Steam" nocase
        $reg3 = "InstallPath" nocase
        $reg4 = "SteamPath" nocase
    condition:
        any of them
}

rule Steam_Credential_Exfiltration {
    meta:
        description = "【严重】疑似外传 Steam 凭证"
        severity = "critical"
        category = "数据外传"
    strings:
        // Steam 相关关键词
        $steam1 = "steam" nocase
        $steam2 = "ssfn" nocase
        $steam3 = "loginusers" nocase
        // 结合网络上传
        $net1 = "webhook" nocase
        $net2 = "discord.com/api" nocase
        $net3 = "telegram" nocase
        $net4 = "pastebin" nocase
        $upload1 = "upload" nocase
        $upload2 = "POST" nocase
    condition:
        any of ($steam*) and (any of ($net*) or any of ($upload*))
}
rule Steam_ID_Collection {
    meta:
        description = "【中危】收集 Steam ID 信息"
        severity = "medium"
        category = "信息收集"
    strings:
        $id1 = "GetSteamID" nocase
        $id2 = "SteamID64" nocase
        $id3 = "SteamID32" nocase
        $id4 = "CSteamID" nocase
        $id5 = "steam3Id" nocase
        // 转换相关
        $conv1 = "ConvertToUInt64" nocase
        $conv2 = "ToString" nocase
    condition:
        2 of ($id*) or (any of ($id*) and any of ($conv*))
}

rule Steam_ID_With_Network {
    meta:
        description = "【高危】获取 Steam ID 并发送网络请求"
        severity = "high"
        category = "数据外传"
    strings:
        $id1 = "GetSteamID" nocase
        $id2 = "SteamID" nocase
        $id3 = "CSteamID" nocase
        // 网络
        $net1 = "WebClient" nocase
        $net2 = "HttpClient" nocase
        $net3 = "WebRequest" nocase
        $net4 = "discord.com" nocase
        $net5 = "webhook" nocase
    condition:
        any of ($id*) and any of ($net*)
}

rule Steam_AuthTicket_Theft {
    meta:
        description = "【严重】窃取 Steam 认证票据"
        severity = "critical"
        category = "凭证窃取"
    strings:
        $auth1 = "GetAuthSessionTicket" nocase
        $auth2 = "AuthSessionTicket" nocase
        $auth3 = "BeginAuthSession" nocase
        $auth4 = "GetAuthToken" nocase
        // 编码/发送
        $enc1 = "ToBase64String" nocase
        $enc2 = "BitConverter" nocase
        $send1 = "Upload" nocase
        $send2 = "Post" nocase
        $send3 = "Send" nocase
    condition:
        any of ($auth*) and (any of ($enc*) or any of ($send*))
}

rule Steam_PersonaName_Exfil {
    meta:
        description = "【中危】收集 Steam 用户名"
        severity = "medium"
        category = "信息收集"
    strings:
        $name1 = "GetPersonaName" nocase
        $name2 = "PersonaName" nocase
        $name3 = "GetFriendPersonaName" nocase
        // 外传
        $net1 = "webhook" nocase
        $net2 = "discord" nocase
        $net3 = "telegram" nocase
        $net4 = "HttpClient" nocase
    condition:
        any of ($name*) and any of ($net*)
}

rule Steam_Friends_Enumeration {
    meta:
        description = "【中危】枚举 Steam 好友列表"
        severity = "medium"  
        category = "信息收集"
    strings:
        $friend1 = "GetFriendCount" nocase
        $friend2 = "GetFriendByIndex" nocase
        $friend3 = "GetFriendsList" nocase
        $friend4 = "FriendsList" nocase
    condition:
        2 of them
}

rule Steam_Inventory_Access {
    meta:
        description = "【高危】访问 Steam 库存信息"
        severity = "high"
        category = "资产访问"
    strings:
        $inv1 = "GetAllItems" nocase
        $inv2 = "GetInventory" nocase
        $inv3 = "GetItemsByID" nocase
        $inv4 = "IInventory" nocase
        $inv5 = "ISteamInventory" nocase
        // 市场价值
        $market1 = "market_hash_name" nocase
        $market2 = "GetItemPrice" nocase
    condition:
        2 of them
}