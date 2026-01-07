"""
核心工具函数
"""
import re
from typing import List, Set


def extract_urls(content: str) -> List[str]:
    """提取文本中的 URL"""
    url_pattern = r'https?://[^\s<>"\')\]]+' 
    return re.findall(url_pattern, content, re.IGNORECASE)


def extract_ips(content: str) -> List[str]:
    """提取 IP 地址"""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(ip_pattern, content)


def extract_file_paths(content: str) -> List[str]:
    """提取文件路径"""
    # Windows 路径
    win_pattern = r'[A-Za-z]:\\[^\s<>"\'*?|]+' 
    # Unix 路径
    unix_pattern = r'/(?:[^\s<>"\'*?|]+/)*[^\s<>"\'*?|]+'
    
    paths = re.findall(win_pattern, content)
    paths.extend(re.findall(unix_pattern, content))
    return paths


def extract_registry_keys(content: str) -> List[str]:
    """提取注册表键"""
    reg_pattern = r'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKU|HKCR)\\[^\s<>"\']+' 
    return re.findall(reg_pattern, content, re.IGNORECASE)


def detect_obfuscation(content: str) -> dict:
    """检测代码混淆特征"""
    result = {
        'is_obfuscated': False,
        'indicators': [],
        'confidence': 0.0
    }
    
    indicators = []
    
    # 大量 Base64
    b64_pattern = r'[A-Za-z0-9+/]{50,}={0,2}'
    b64_matches = re.findall(b64_pattern, content)
    if len(b64_matches) > 2:
        indicators.append(f"Base64 编码块: {len(b64_matches)} 处")
        
    # 十六进制字符串
    hex_pattern = r'\\x[0-9a-fA-F]{2}'
    hex_matches = re.findall(hex_pattern, content)
    if len(hex_matches) > 20:
        indicators.append(f"十六进制转义: {len(hex_matches)} 处")
        
    # 动态执行
    exec_patterns = ['eval(', 'exec(', 'compile(', 'Function(', 'setTimeout(']
    for pattern in exec_patterns:
        if pattern in content:
            indicators.append(f"动态执行: {pattern}")
            
    # 字符串拼接混淆
    concat_pattern = r'["\'][^"\']{1,3}["\'](\s*\+\s*["\'][^"\']{1,3}["\']){5,}'
    if re.search(concat_pattern, content):
        indicators.append("字符串拼接混淆")
        
    result['indicators'] = indicators
    result['confidence'] = min(1.0, len(indicators) * 0.25)
    result['is_obfuscated'] = result['confidence'] > 0.5
    
    return result


def calculate_entropy(data: bytes) -> float:
    """计算数据熵值 (用于检测加密/压缩内容)"""
    if not data:
        return 0.0
        
    import math
    from collections import Counter
    
    counter = Counter(data)
    length = len(data)
    
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy


def is_high_entropy(data: bytes, threshold: float = 7.0) -> bool:
    """检查是否为高熵数据 (可能是加密/压缩)"""
    return calculate_entropy(data) > threshold


def sanitize_path(path: str) -> str:
    """清理路径中的敏感信息"""
    # 替换用户名
    import os
    username = os.getenv('USERNAME', 'user')
    path = path.replace(username, '<USER>')
    return path


def get_file_signature(data: bytes) -> str:
    """获取文件魔数签名"""
    signatures = {
        b'MZ': 'PE Executable',
        b'PK': 'ZIP Archive',
        b'\x7fELF': 'ELF Executable',
        b'Rar!': 'RAR Archive',
        b'7z\xbc\xaf': '7z Archive',
        b'\x89PNG': 'PNG Image',
        b'GIF8': 'GIF Image',
        b'\xff\xd8\xff': 'JPEG Image',
    }
    
    for sig, name in signatures.items():
        if data.startswith(sig):
            return name
            
    return 'Unknown'
