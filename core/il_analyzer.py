"""
.NET IL 智能分析器 v2.0
增强版：上下文感知 + 白名单机制 + 行为组合分析
"""
import os
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

try:
    import dnfile
    from dnfile import dnPE
    DNFILE_AVAILABLE = True
except ImportError:
    DNFILE_AVAILABLE = False


class APICategory(Enum):
    """API 分类"""
    FILESYSTEM = "文件系统"
    NETWORK = "网络通信"
    PROCESS = "进程执行"
    REGISTRY = "注册表"
    CRYPTO = "加密解密"
    REFLECTION = "反射调用"
    STEAM = "Steam相关"
    UNKNOWN = "未知"


class RiskLevel(Enum):
    """风险等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


@dataclass
class APISignature:
    """API 签名定义"""
    pattern: str
    category: APICategory
    base_severity: str
    description: str
    requires_context: List[str] = field(default_factory=list)
    safe_contexts: List[str] = field(default_factory=list)


@dataclass
class ILFinding:
    """IL 分析发现"""
    file_path: Path
    api_name: str
    category: APICategory
    severity: str
    description: str
    context: str = ""
    is_contextual: bool = False
    mitigated: bool = False
    
    def to_dict(self) -> Dict:
        return {
            'file': str(self.file_path),
            'api': self.api_name,
            'category': self.category.value,
            'severity': self.severity,
            'description': self.description,
            'context': self.context,
            'is_contextual': self.is_contextual,
            'mitigated': self.mitigated,
        }


# 向后兼容的别名
@dataclass
class DangerousAPI:
    """危险 API 记录 (兼容旧版)"""
    full_name: str
    category: APICategory
    severity: str
    description: str


class ILAnalyzer:
    """
    智能 IL 分析器
    
    核心改进:
    1. 白名单机制 - 已知安全的 Mod 框架不报警
    2. 上下文分析 - 单独的 API 调用不危险，组合才危险
    3. 行为意图分析 - 判断是正常功能还是恶意行为
    """
    
    # ===== 已知安全的 Mod 框架 =====
    TRUSTED_FRAMEWORKS = {
        # Unity Mod 框架
        "BepInEx", "BepInEx.Core", "BepInEx.Unity",
        "MelonLoader", "MelonLoader.Core",
        "MonoMod", "MonoMod.RuntimeDetour",
        "HarmonyLib", "0Harmony", "Harmony",
        # 常用库
        "Newtonsoft.Json", "Newtonsoft.Json.Linq",
        "System.Linq", "System.Collections.Generic",
        "UnityEngine", "UnityEngine.CoreModule",
        "Assembly-CSharp",
        # 日志库
        "NLog", "log4net", "Serilog",
    }
    
    # ===== 安全的 API 使用场景 =====
    SAFE_PATTERNS = {
        "Harmony": ["Assembly::Load", "MethodInfo", "Reflection"],
        "BepInEx": ["Assembly::Load", "Process", "GetCurrentProcess"],
        "UnityEngine": ["File::ReadAllBytes", "StreamReader"],
        "Newtonsoft": ["File::ReadAllText", "File::WriteAllText"],
    }
    
    # ===== 真正危险的行为组合 =====
    DANGEROUS_COMBINATIONS = [
        {
            "name": "Steam凭证窃取",
            "requires": ["ssfn", "loginusers", "config.vdf"],
            "and_any": ["WebClient", "HttpClient", "Upload", "Post", "webhook"],
            "severity": "critical",
            "description": "读取 Steam 敏感文件并可能外传"
        },
        {
            "name": "下载并执行",
            "requires": ["Download", "WebClient::Download", "HttpClient"],
            "and_any": ["Process::Start", "Assembly::Load", "Invoke"],
            "severity": "critical", 
            "description": "下载外部代码并执行，高危行为"
        },
        {
            "name": "疑似键盘记录",
            "requires": ["GetAsyncKeyState", "SetWindowsHookEx", "KeyboardHook"],
            "and_any": ["File::Write", "WebClient", "Send"],
            "severity": "critical",
            "description": "可能记录键盘输入"
        },
        # === 新增组合检测 ===
        {
            "name": "Steam ID 外传",
            "requires": ["GetSteamID", "SteamID", "CSteamID"],
            "and_any": ["WebClient", "HttpClient", "Upload", "Post", "webhook", "discord"],
            "severity": "high",
            "description": "获取 Steam ID 并发送到外部服务器"
        },
        {
            "name": "用户信息收集",
            "requires": ["UserName", "MachineName", "GetMACAddress", "HWID"],
            "and_any": ["WebClient", "HttpClient", "Upload", "Post", "Send"],
            "severity": "high",
            "description": "收集用户/系统信息并外传"
        },
        {
            "name": "屏幕监控",
            "requires": ["Screenshot", "CopyFromScreen", "Bitmap"],
            "and_any": ["WebClient", "HttpClient", "Upload", "Send", "Save"],
            "severity": "high",
            "description": "截取屏幕并可能外传"
        },
        {
            "name": "剪贴板劫持",
            "requires": ["Clipboard::GetText", "Clipboard::SetText"],
            "and_any": ["bitcoin", "ethereum", "wallet", "0x", "bc1"],
            "severity": "critical",
            "description": "可能替换加密货币钱包地址"
        },
        {
            "name": "Steam认证票据窃取",
            "requires": ["GetAuthSessionTicket", "AuthTicket"],
            "and_any": ["WebClient", "HttpClient", "Upload", "Send", "Convert"],
            "severity": "critical",
            "description": "窃取 Steam 认证票据，可能用于账号劫持"
        },
        {
            "name": "Discord Webhook 外传",
            "requires": ["discord.com/api/webhooks"],
            "and_any": ["SteamID", "password", "token", "credential", "ssfn", "File::Read"],
            "severity": "critical",
            "description": "通过 Discord Webhook 外传敏感数据"
        },
        {
            "name": "持久化安装",
            "requires": ["Registry::SetValue", "Run", "RunOnce"],
            "and_any": ["CurrentVersion", "startup", "autorun"],
            "severity": "high",
            "description": "尝试将自身添加到系统启动项"
        },
        {
            "name": "可疑框架伪装",
            "requires": ["0Harmony", "BepInEx", "MelonLoader"],  # 文件名看起来像框架
            "and_any": ["ssfn", "loginusers", "webhook", "Upload", "keylogger", "screenshot"],
            "severity": "critical",
            "description": "⚠️ 文件伪装成 Mod 框架但包含恶意行为"
        },
    ]
    
    def __init__(self):
        self.signatures: Dict[str, APISignature] = {}
        self.dangerous_apis: Dict[str, DangerousAPI] = {}  # 兼容旧版
        self._init_signatures()
        
    def _init_signatures(self):
        """初始化 API 签名库"""
        
        # === 文件系统 API ===
        file_apis = [
            APISignature(
                pattern="System.IO.File::ReadAllText",
                category=APICategory.FILESYSTEM,
                base_severity="low",
                description="读取文本文件",
                requires_context=["ssfn", "loginusers", "password", "credential"],
                safe_contexts=["config", "settings", "json", "xml", "log"]
            ),
            APISignature(
                pattern="System.IO.File::ReadAllBytes",
                category=APICategory.FILESYSTEM,
                base_severity="low",
                description="读取二进制文件",
                requires_context=["ssfn", "loginusers", "Steam"],
                safe_contexts=["asset", "resource", "texture", "audio"]
            ),
            APISignature(
                pattern="System.IO.File::Copy",
                category=APICategory.FILESYSTEM,
                base_severity="low",
                description="复制文件",
                safe_contexts=["backup", "cache", "temp"]
            ),
            APISignature(
                pattern="System.IO.File::Move",
                category=APICategory.FILESYSTEM,
                base_severity="low",
                description="移动文件",
            ),
            APISignature(
                pattern="System.IO.Directory::GetFiles",
                category=APICategory.FILESYSTEM,
                base_severity="info",
                description="列出目录文件",
            ),
        ]
        
        # === 网络 API ===
        network_apis = [
            APISignature(
                pattern="System.Net.WebClient::UploadData",
                category=APICategory.NETWORK,
                base_severity="high",
                description="上传数据到服务器",
                requires_context=["ssfn", "Steam", "password", "token"],
            ),
            APISignature(
                pattern="System.Net.WebClient::UploadFile",
                category=APICategory.NETWORK,
                base_severity="high",
                description="上传文件到服务器",
            ),
            APISignature(
                pattern="System.Net.WebClient::UploadString",
                category=APICategory.NETWORK,
                base_severity="high",
                description="上传字符串到服务器",
            ),
            APISignature(
                pattern="System.Net.WebClient::DownloadString",
                category=APICategory.NETWORK,
                base_severity="low",
                description="下载文本内容",
                safe_contexts=["update", "version", "api", "config"]
            ),
            APISignature(
                pattern="System.Net.WebClient::DownloadFile",
                category=APICategory.NETWORK,
                base_severity="medium",
                description="下载文件",
                requires_context=["exe", "dll", "Process::Start"],
            ),
            APISignature(
                pattern="System.Net.Http.HttpClient",
                category=APICategory.NETWORK,
                base_severity="info",
                description="HTTP 客户端 (常见网络库)",
            ),
            APISignature(
                pattern="System.Net.Http.HttpClient::PostAsync",
                category=APICategory.NETWORK,
                base_severity="medium",
                description="HTTP POST 请求",
                requires_context=["ssfn", "password", "credential"],
            ),
        ]
        
        # === 进程执行 API ===
        process_apis = [
            APISignature(
                pattern="System.Diagnostics.Process::Start",
                category=APICategory.PROCESS,
                base_severity="medium",
                description="启动外部进程",
                requires_context=["cmd", "powershell", "hidden", "Download"],
                safe_contexts=["explorer", "browser", "url", "steam://", "open"]
            ),
            APISignature(
                pattern="System.Reflection.Assembly::Load",
                category=APICategory.REFLECTION,
                base_severity="low",
                description="动态加载程序集 (Mod框架常用)",
                safe_contexts=["Harmony", "BepInEx", "MelonLoader", "plugin"]
            ),
            APISignature(
                pattern="System.Reflection.Assembly::LoadFrom",
                category=APICategory.REFLECTION,
                base_severity="low",
                description="从文件加载程序集",
                safe_contexts=["plugins", "mods", "addons"]
            ),
            APISignature(
                pattern="System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer",
                category=APICategory.PROCESS,
                base_severity="medium",
                description="函数指针转换 (可能用于Native调用)",
            ),
        ]
        
        # === 注册表 API ===
        registry_apis = [
            APISignature(
                pattern="Microsoft.Win32.Registry::GetValue",
                category=APICategory.REGISTRY,
                base_severity="low",
                description="读取注册表",
                safe_contexts=["Steam", "InstallPath", "settings"]
            ),
            APISignature(
                pattern="Microsoft.Win32.Registry::SetValue",
                category=APICategory.REGISTRY,
                base_severity="medium",
                description="写入注册表",
                requires_context=["Run", "RunOnce", "startup"],
            ),
        ]
        
        # === 加密 API ===
        crypto_apis = [
            APISignature(
                pattern="System.Security.Cryptography.Aes",
                category=APICategory.CRYPTO,
                base_severity="info",
                description="AES 加密 (常用加密算法)",
                requires_context=["File::ReadAll", "ransom", "encrypt"],
            ),
            APISignature(
                pattern="System.Convert::FromBase64String",
                category=APICategory.CRYPTO,
                base_severity="info",
                description="Base64 解码",
            ),
            APISignature(
                pattern="System.Convert::ToBase64String",
                category=APICategory.CRYPTO,
                base_severity="info",
                description="Base64 编码",
            ),
        ]
        
        # === Steam 专项 (这些始终危险) ===
        steam_apis = [
            APISignature(
                pattern="ssfn",
                category=APICategory.STEAM,
                base_severity="critical",
                description="⚠️ 访问 Steam 授权令牌 (极其敏感)",
            ),
            APISignature(
                pattern="loginusers.vdf",
                category=APICategory.STEAM,
                base_severity="critical",
                description="⚠️ 访问 Steam 登录用户信息",
            ),
            APISignature(
                pattern="config.vdf",
                category=APICategory.STEAM,
                base_severity="high",
                description="访问 Steam 配置文件",
                requires_context=["File::Read", "StreamReader"],
            ),
            # === 新增：Steam ID 相关检测 ===
            APISignature(
                pattern="Steamworks.SteamUser::GetSteamID",
                category=APICategory.STEAM,
                base_severity="medium",
                description="获取当前用户 Steam ID",
                requires_context=["WebClient", "HttpClient", "Upload", "Post", "Send"],
                safe_contexts=["leaderboard", "achievement", "multiplayer", "lobby"]
            ),
            APISignature(
                pattern="CSteamID",
                category=APICategory.STEAM,
                base_severity="low",
                description="使用 Steam ID 结构",
                requires_context=["ToString", "WebClient", "HttpClient", "Send"],
            ),
            APISignature(
                pattern="GetSteamID",
                category=APICategory.STEAM,
                base_severity="medium",
                description="获取 Steam ID",
                requires_context=["WebClient", "HttpClient", "Upload", "Post"],
                safe_contexts=["multiplayer", "lobby", "match", "server"]
            ),
            APISignature(
                pattern="SteamAPI_ISteamUser",
                category=APICategory.STEAM,
                base_severity="low",
                description="调用 Steam 用户 API",
                requires_context=["GetAuthSessionTicket", "token", "credential"],
            ),
            APISignature(
                pattern="GetAuthSessionTicket",
                category=APICategory.STEAM,
                base_severity="high",
                description="⚠️ 获取 Steam 认证票据 (敏感)",
                requires_context=["WebClient", "HttpClient", "Upload"],
            ),
            APISignature(
                pattern="GetPersonaName",
                category=APICategory.STEAM,
                base_severity="low",
                description="获取 Steam 用户名",
                requires_context=["WebClient", "HttpClient", "Upload", "discord"],
            ),
            APISignature(
                pattern="steamcommunity.com",
                category=APICategory.STEAM,
                base_severity="low",
                description="访问 Steam 社区",
                requires_context=["inventory", "trade", "market"],
            ),
            # === Steam 路径访问 ===
            APISignature(
                pattern="Steam\\\\config",
                category=APICategory.STEAM,
                base_severity="high",
                description="访问 Steam 配置目录",
            ),
            APISignature(
                pattern="Steam\\\\userdata",
                category=APICategory.STEAM,
                base_severity="medium",
                description="访问 Steam 用户数据目录",
                requires_context=["File::Read", "Directory::GetFiles", "Copy"],
            ),
        ]
        
        # === 新增：敏感信息收集 ===
        sensitive_apis = [
            APISignature(
                pattern="Environment::UserName",
                category=APICategory.UNKNOWN,
                base_severity="low",
                description="获取系统用户名",
                requires_context=["WebClient", "HttpClient", "Send", "Upload"],
            ),
            APISignature(
                pattern="Environment::MachineName",
                category=APICategory.UNKNOWN,
                base_severity="low",
                description="获取计算机名",
                requires_context=["WebClient", "HttpClient", "Send"],
            ),
            APISignature(
                pattern="GetMACAddress",
                category=APICategory.NETWORK,
                base_severity="medium",
                description="获取 MAC 地址 (硬件指纹)",
                requires_context=["WebClient", "HttpClient", "Send"],
            ),
            APISignature(
                pattern="PhysicalAddress",
                category=APICategory.NETWORK,
                base_severity="medium",
                description="获取物理网络地址",
                requires_context=["WebClient", "HttpClient", "Upload"],
            ),
            APISignature(
                pattern="HWID",
                category=APICategory.UNKNOWN,
                base_severity="medium",
                description="获取硬件 ID (设备指纹)",
            ),
            APISignature(
                pattern="ManagementObject",
                category=APICategory.UNKNOWN,
                base_severity="low",
                description="WMI 查询 (可获取系统信息)",
                requires_context=["SerialNumber", "UUID", "BIOS", "WebClient"],
            ),
            APISignature(
                pattern="discord.com/api/webhooks",
                category=APICategory.NETWORK,
                base_severity="high",
                description="⚠️ Discord Webhook (常用于数据外传)",
            ),
            APISignature(
                pattern="telegram.org",
                category=APICategory.NETWORK,
                base_severity="high",
                description="⚠️ Telegram API (可能用于数据外传)",
            ),
            APISignature(
                pattern="api.ipify.org",
                category=APICategory.NETWORK,
                base_severity="medium",
                description="获取外网 IP 地址",
                requires_context=["WebClient", "HttpClient"],
            ),
        ]
        
        # === 新增：恶意行为模式 ===
        malicious_apis = [
            APISignature(
                pattern="Clipboard::GetText",
                category=APICategory.UNKNOWN,
                base_severity="medium",
                description="读取剪贴板内容",
                requires_context=["WebClient", "HttpClient", "Send"],
            ),
            APISignature(
                pattern="Clipboard::SetText",
                category=APICategory.UNKNOWN,
                base_severity="medium",
                description="修改剪贴板内容 (可能替换钱包地址)",
            ),
            APISignature(
                pattern="Screenshot",
                category=APICategory.UNKNOWN,
                base_severity="medium",
                description="截屏功能",
                requires_context=["WebClient", "Upload", "Send", "HttpClient"],
            ),
            APISignature(
                pattern="CopyFromScreen",
                category=APICategory.UNKNOWN,
                base_severity="medium",
                description="屏幕截图",
                requires_context=["WebClient", "Upload", "Send"],
            ),
            APISignature(
                pattern="SetWindowsHookEx",
                category=APICategory.PROCESS,
                base_severity="high",
                description="⚠️ 设置系统钩子 (可能监控输入)",
            ),
            APISignature(
                pattern="GetAsyncKeyState",
                category=APICategory.PROCESS,
                base_severity="high",
                description="⚠️ 检测按键状态 (键盘记录特征)",
            ),
            APISignature(
                pattern="keybd_event",
                category=APICategory.PROCESS,
                base_severity="medium",
                description="模拟键盘输入",
            ),
            APISignature(
                pattern="mouse_event",
                category=APICategory.PROCESS,
                base_severity="low",
                description="模拟鼠标输入",
            ),
        ]
        
        # 注册所有签名
        for api_list in [file_apis, network_apis, process_apis, registry_apis, crypto_apis, steam_apis, sensitive_apis, malicious_apis]:
            for sig in api_list:
                self.signatures[sig.pattern] = sig
                # 兼容旧版 API
                self.dangerous_apis[sig.pattern] = DangerousAPI(
                    full_name=sig.pattern,
                    category=sig.category,
                    severity=sig.base_severity,
                    description=sig.description
                )
                
    def analyze_file(self, file_path: Path) -> List[ILFinding]:
        """分析单个 .NET 文件"""
        if not DNFILE_AVAILABLE:
            return []
            
        findings = []
        
        try:
            pe = dnfile.dnPE(str(file_path))
            
            if pe.net is None:
                return []
            
            # 提取所有引用
            all_refs = self._extract_all_references(pe)
            
            # 检查是否是已知安全框架
            is_trusted = self._is_trusted_assembly(file_path, all_refs)
            
            # 检查危险组合 (最高优先级)
            combo_findings = self._check_dangerous_combinations(file_path, all_refs)
            findings.extend(combo_findings)
            
            # 检查单个 API（考虑上下文）
            for ref in all_refs:
                finding = self._analyze_single_api(file_path, ref, all_refs, is_trusted)
                if finding:
                    findings.append(finding)
                    
            # 去重
            findings = self._deduplicate_findings(findings)
                        
        except Exception:
            pass
            
        return findings
    
    def _is_trusted_assembly(self, file_path: Path, refs: Set[str]) -> bool:
        """
        检查是否是可信程序集
        
        注意：这只是辅助判断，不能完全信任！
        恶意文件可能伪装成可信框架的文件名。
        即使返回 True，危险行为仍会被检测和报告。
        """
        file_name = file_path.stem
        refs_str = " ".join(refs).lower()
        
        # 如果包含明显恶意特征，即使名称可信也不信任
        malicious_indicators = [
            "ssfn", "loginusers.vdf", "config.vdf",  # Steam 凭证
            "discord.com/api/webhooks", "telegram.org",  # 数据外传
            "keylogger", "screenshot", "clipboard",  # 监控行为
            "confuserex", "dotfuscator", "obfuscar",  # 混淆器
        ]
        for indicator in malicious_indicators:
            if indicator in refs_str or indicator in file_name.lower():
                return False  # 存在恶意指标，不信任
        
        # 检查文件名是否包含可信框架名
        for trusted in self.TRUSTED_FRAMEWORKS:
            if trusted.lower() in file_name.lower():
                # 额外验证：可信框架应该也引用了框架库
                # 单独一个 "0Harmony.dll" 不引用任何框架库是可疑的
                has_framework_ref = any(
                    t.lower() in refs_str for t in self.TRUSTED_FRAMEWORKS
                )
                return has_framework_ref
                
        # 检查是否引用了 Mod 框架
        for ref in refs:
            for trusted in self.TRUSTED_FRAMEWORKS:
                if trusted in ref:
                    return True
                    
        return False
    
    def _check_dangerous_combinations(
        self, 
        file_path: Path, 
        refs: Set[str]
    ) -> List[ILFinding]:
        """检查危险的 API 组合"""
        findings = []
        refs_lower = {r.lower() for r in refs}
        refs_str = " ".join(refs_lower)
        file_name_lower = file_path.stem.lower()
        
        # 将文件名也加入检查范围（检测伪装框架）
        combined_str = refs_str + " " + file_name_lower
        
        for combo in self.DANGEROUS_COMBINATIONS:
            # 检查必需条件（在代码引用或文件名中）
            has_required = any(
                req.lower() in combined_str for req in combo["requires"]
            )
            
            if not has_required:
                continue
                
            # 检查附加条件
            has_additional = any(
                add.lower() in combined_str for add in combo["and_any"]
            )
            
            if has_additional:
                finding = ILFinding(
                    file_path=file_path,
                    api_name=combo["name"],
                    category=APICategory.UNKNOWN,
                    severity=combo["severity"],
                    description=combo["description"],
                    is_contextual=True,
                    context=f"组合检测: {combo['requires'][:2]} + {combo['and_any'][:2]}"
                )
                findings.append(finding)
                
        return findings
    
    def _analyze_single_api(
        self,
        file_path: Path,
        ref: str,
        all_refs: Set[str],
        is_trusted: bool
    ) -> Optional[ILFinding]:
        """分析单个 API 调用"""
        
        for pattern, sig in self.signatures.items():
            if pattern.lower() not in ref.lower():
                continue
                
            # 计算实际严重程度
            actual_severity = self._calculate_severity(sig, all_refs, is_trusted)
            
            # 如果降级到 safe 或 info，且是可信程序集，不报告
            if actual_severity in ["safe", "info"] and is_trusted:
                continue
                
            # 如果是 safe，不报告
            if actual_severity == "safe":
                continue
            
            return ILFinding(
                file_path=file_path,
                api_name=pattern,
                category=sig.category,
                severity=actual_severity,
                description=self._get_contextual_description(sig, all_refs, is_trusted),
                context=ref[:100],
                mitigated=is_trusted
            )
            
        return None
    
    def _calculate_severity(
        self, 
        sig: APISignature, 
        all_refs: Set[str],
        is_trusted: bool
    ) -> str:
        """计算实际严重程度（考虑上下文）"""
        severity = sig.base_severity
        refs_lower = " ".join(all_refs).lower()
        
        # Steam 相关始终保持原级别
        if sig.category == APICategory.STEAM:
            return severity
        
        # 检查是否有安全上下文 → 降级
        for safe_ctx in sig.safe_contexts:
            if safe_ctx.lower() in refs_lower:
                severity = self._downgrade_severity(severity)
                break
                
        # 检查是否有危险上下文 → 升级
        for danger_ctx in sig.requires_context:
            if danger_ctx.lower() in refs_lower:
                severity = self._upgrade_severity(severity)
                break
        
        # 可信程序集再降一级（除了 critical）
        if is_trusted and severity not in ["critical", "high"]:
            severity = self._downgrade_severity(severity)
            
        return severity
    
    def _upgrade_severity(self, severity: str) -> str:
        """升级严重程度"""
        levels = ["safe", "info", "low", "medium", "high", "critical"]
        idx = levels.index(severity) if severity in levels else 2
        return levels[min(idx + 1, len(levels) - 1)]
    
    def _downgrade_severity(self, severity: str) -> str:
        """降级严重程度"""
        levels = ["safe", "info", "low", "medium", "high", "critical"]
        idx = levels.index(severity) if severity in levels else 2
        return levels[max(idx - 1, 0)]
    
    def _get_contextual_description(
        self, 
        sig: APISignature, 
        all_refs: Set[str],
        is_trusted: bool
    ) -> str:
        """获取上下文相关的描述"""
        desc = sig.description
        
        if is_trusted:
            desc += " (Mod框架正常使用)"
            
        refs_lower = " ".join(all_refs).lower()
        
        if "harmony" in refs_lower:
            desc += " [Harmony]"
        elif "bepinex" in refs_lower:
            desc += " [BepInEx]"
        elif "melonloader" in refs_lower:
            desc += " [MelonLoader]"
            
        return desc
    
    def _extract_all_references(self, pe: 'dnPE') -> Set[str]:
        """提取所有引用"""
        refs = set()
        
        try:
            # MemberRef 表
            if hasattr(pe.net.mdtables, 'MemberRef') and pe.net.mdtables.MemberRef:
                for row in pe.net.mdtables.MemberRef:
                    if hasattr(row, 'Name') and row.Name:
                        member_name = str(row.Name)
                        class_name = self._resolve_member_class(pe, row)
                        if class_name:
                            refs.add(f"{class_name}::{member_name}")
                        refs.add(member_name)
            
            # TypeRef 表
            if hasattr(pe.net.mdtables, 'TypeRef') and pe.net.mdtables.TypeRef:
                for row in pe.net.mdtables.TypeRef:
                    if hasattr(row, 'TypeNamespace') and hasattr(row, 'TypeName'):
                        ns = str(row.TypeNamespace) if row.TypeNamespace else ""
                        name = str(row.TypeName) if row.TypeName else ""
                        full_name = f"{ns}.{name}" if ns else name
                        refs.add(full_name)
                        
            # AssemblyRef 表
            if hasattr(pe.net.mdtables, 'AssemblyRef') and pe.net.mdtables.AssemblyRef:
                for row in pe.net.mdtables.AssemblyRef:
                    if hasattr(row, 'Name') and row.Name:
                        refs.add(str(row.Name))
                            
            # 用户字符串
            refs.update(self._extract_user_strings(pe))
                            
        except Exception:
            pass
            
        return refs
    
    def _resolve_member_class(self, pe: 'dnPE', member_row) -> Optional[str]:
        """解析成员所属的类"""
        try:
            if hasattr(member_row, 'Class') and member_row.Class:
                class_ref = member_row.Class
                if hasattr(class_ref, 'row') and class_ref.row:
                    row = class_ref.row
                    if hasattr(row, 'TypeNamespace') and hasattr(row, 'TypeName'):
                        ns = str(row.TypeNamespace) if row.TypeNamespace else ""
                        name = str(row.TypeName) if row.TypeName else ""
                        return f"{ns}.{name}" if ns else name
        except Exception:
            pass
        return None
    
    def _extract_user_strings(self, pe: 'dnPE') -> Set[str]:
        """提取用户字符串中的敏感内容"""
        strings = set()
        
        keywords = [
            'ssfn', 'loginusers', 'config.vdf',
            'password', 'credential', 'token',
            'discord.com/api/webhooks', 'telegram.org',
        ]
        
        try:
            if hasattr(pe.net, 'user_strings') and pe.net.user_strings:
                for us in pe.net.user_strings:
                    if us and isinstance(us, str):
                        lower_str = us.lower()
                        for keyword in keywords:
                            if keyword in lower_str:
                                strings.add(f"STRING:{us[:80]}")
                                break
        except Exception:
            pass
            
        return strings
    
    def _deduplicate_findings(self, findings: List[ILFinding]) -> List[ILFinding]:
        """去重"""
        seen = set()
        unique = []
        
        for f in findings:
            key = (str(f.file_path), f.api_name, f.severity)
            if key not in seen:
                seen.add(key)
                unique.append(f)
                
        return unique
    
    def is_dotnet_assembly(self, file_path: Path) -> bool:
        """检查是否是 .NET 程序集"""
        if not DNFILE_AVAILABLE:
            return False
        try:
            pe = dnfile.dnPE(str(file_path))
            return pe.net is not None
        except Exception:
            return False
    
    def analyze_directory(
        self, 
        target_dir: Path,
        progress_callback=None
    ) -> List[ILFinding]:
        """分析目录"""
        all_findings = []
        
        dotnet_files = list(target_dir.rglob("*.dll")) + list(target_dir.rglob("*.exe"))
        total = len(dotnet_files)
        
        for idx, file_path in enumerate(dotnet_files):
            if progress_callback:
                progress_callback(file_path.name, idx, total)
                
            findings = self.analyze_file(file_path)
            all_findings.extend(findings)
            
        return all_findings
    
    def get_summary(self, findings: List[ILFinding]) -> Dict:
        """生成分析摘要"""
        summary = {
            'total_findings': len(findings),
            'by_category': {},
            'by_severity': {},
            'critical_apis': [],
        }
        
        for finding in findings:
            cat = finding.category.value
            summary['by_category'][cat] = summary['by_category'].get(cat, 0) + 1
            
            sev = finding.severity
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1
            
            if sev == 'critical':
                summary['critical_apis'].append(finding.api_name)
                
        return summary


# === 便捷函数 ===
def quick_analyze(file_path: str) -> List[Dict]:
    """快速分析"""
    analyzer = ILAnalyzer()
    findings = analyzer.analyze_file(Path(file_path))
    return [f.to_dict() for f in findings]
