"""
ModGuard 2.0 - 全局配置
"""
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict

# === 路径配置 ===
BASE_DIR = Path(__file__).parent.resolve()
RULES_DIR = BASE_DIR / "rules"
ASSETS_DIR = BASE_DIR / "assets"
LOGS_DIR = BASE_DIR / "logs"

# === 应用信息 ===
APP_NAME = "ModGuard"
APP_VERSION = "2.0.0"
APP_AUTHOR = "ModGuard Team"

@dataclass
class ScanConfig:
    """扫描配置"""
    # 扫描的文件类型
    target_extensions: List[str] = field(default_factory=lambda: [
        # 脚本类
        '.lua', '.py', '.js', '.vbs', '.ps1', '.bat', '.sh',
        # 可执行类
        '.dll', '.exe', '.so',
        # 配置类
        '.cfg', '.vdf', '.json', '.xml', '.ini',
        # 资源类 (可能藏恶意代码)
        '.txt', '.md',
    ])
    
    # .NET 分析专用扩展名
    dotnet_extensions: List[str] = field(default_factory=lambda: ['.dll', '.exe'])
    
    # 跳过的目录
    skip_dirs: List[str] = field(default_factory=lambda: [
        '__pycache__', '.git', '.svn', 'node_modules', '.venv', 'venv'
    ])
    
    # 最大文件大小 (字节) - 超过此大小跳过
    max_file_size: int = 50 * 1024 * 1024  # 50MB
    
    # 扫描深度
    max_depth: int = 20


@dataclass 
class SteamConfig:
    """Steam 相关配置"""
    # Steam 默认安装路径 (Windows)
    default_paths: List[str] = field(default_factory=lambda: [
        r"C:\Program Files (x86)\Steam",
        r"C:\Program Files\Steam",
        r"D:\Steam",
        r"E:\Steam",
    ])
    
    # Steam 敏感文件 (被读取=高危)
    sensitive_files: List[str] = field(default_factory=lambda: [
        "ssfn*",                    # Steam授权令牌
        "loginusers.vdf",           # 登录用户信息
        "config/config.vdf",        # 配置文件(含密钥)
        "config/loginusers.vdf",
    ])
    
    # Steam 注册表路径
    registry_key: str = r"SOFTWARE\WOW6432Node\Valve\Steam"


@dataclass
class ThreatLevel:
    """威胁等级定义"""
    CRITICAL = "critical"       # 🔴 确认恶意
    HIGH = "high"               # 🟠 高度可疑
    MEDIUM = "medium"           # 🟡 敏感行为
    LOW = "low"                 # 🟢 提示信息
    INFO = "info"               # ⚪ 仅供参考


@dataclass
class ILSignature:
    """IL 危险 API 签名"""
    # 文件系统 - 高危操作
    filesystem_critical: List[str] = field(default_factory=lambda: [
        "System.IO.File::ReadAllText",
        "System.IO.File::ReadAllBytes", 
        "System.IO.File::Copy",
        "System.IO.File::Move",
        "System.IO.Directory::GetFiles",
    ])
    
    # 网络 - 数据外传
    network_exfil: List[str] = field(default_factory=lambda: [
        "System.Net.WebClient::UploadData",
        "System.Net.WebClient::UploadFile",
        "System.Net.WebClient::UploadString",
        "System.Net.Http.HttpClient::PostAsync",
        "System.Net.Http.HttpClient::SendAsync",
    ])
    
    # 进程 - 提权/执行
    process_execution: List[str] = field(default_factory=lambda: [
        "System.Diagnostics.Process::Start",
        "System.Reflection.Assembly::Load",
        "System.Reflection.Assembly::LoadFrom",
        "System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer",
    ])
    
    # 注册表 - 持久化
    registry_access: List[str] = field(default_factory=lambda: [
        "Microsoft.Win32.Registry::GetValue",
        "Microsoft.Win32.Registry::SetValue",
        "Microsoft.Win32.RegistryKey::OpenSubKey",
    ])
    
    # 加密 - 可能用于混淆
    crypto_suspicious: List[str] = field(default_factory=lambda: [
        "System.Security.Cryptography.Aes",
        "System.Security.Cryptography.RijndaelManaged",
        "System.Convert::FromBase64String",
        "System.Convert::ToBase64String",
    ])


# === 全局实例 ===
SCAN_CONFIG = ScanConfig()
STEAM_CONFIG = SteamConfig()
THREAT_LEVEL = ThreatLevel()
IL_SIGNATURES = ILSignature()
