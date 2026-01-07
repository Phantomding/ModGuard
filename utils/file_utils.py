"""
文件处理工具
"""
import os
import hashlib
import tempfile
from pathlib import Path
from typing import Optional, List, Tuple

# 支持的压缩格式
ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'}


def get_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    计算文件哈希值
    
    Args:
        file_path: 文件路径
        algorithm: 哈希算法 (md5, sha1, sha256)
        
    Returns:
        哈希值字符串
    """
    hash_obj = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hash_obj.update(chunk)
            
    return hash_obj.hexdigest()


def get_file_hashes(file_path: str) -> dict:
    """计算多种哈希值"""
    return {
        'md5': get_file_hash(file_path, 'md5'),
        'sha1': get_file_hash(file_path, 'sha1'),
        'sha256': get_file_hash(file_path, 'sha256'),
    }


def is_archive(file_path: str) -> bool:
    """检查是否是压缩文件"""
    ext = Path(file_path).suffix.lower()
    return ext in ARCHIVE_EXTENSIONS


def get_file_type(file_path: str) -> str:
    """获取文件类型"""
    ext = Path(file_path).suffix.lower()
    
    type_map = {
        # 可执行
        '.exe': 'executable',
        '.dll': 'library',
        '.so': 'library',
        # 脚本
        '.py': 'python',
        '.lua': 'lua',
        '.js': 'javascript',
        '.vbs': 'vbscript',
        '.ps1': 'powershell',
        '.bat': 'batch',
        '.sh': 'shell',
        # 配置
        '.json': 'json',
        '.xml': 'xml',
        '.cfg': 'config',
        '.ini': 'config',
        '.vdf': 'valve_data',
        # 压缩
        '.zip': 'archive',
        '.rar': 'archive',
        '.7z': 'archive',
    }
    
    return type_map.get(ext, 'unknown')


def is_pe_file(file_path: str) -> bool:
    """检查是否是 PE 文件 (Windows 可执行)"""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(2)
            return header == b'MZ'
    except Exception:
        return False


def is_dotnet_assembly(file_path: str) -> bool:
    """检查是否是 .NET 程序集"""
    try:
        with open(file_path, 'rb') as f:
            content = f.read(1024)
            # .NET 程序集通常包含这些标志
            return b'.text' in content and b'_CorExeMain' in content or b'_CorDllMain' in content
    except Exception:
        return False


def extract_archive(archive_path: str, dest_dir: str = None) -> Tuple[bool, str]:
    """
    解压压缩文件
    
    Args:
        archive_path: 压缩文件路径
        dest_dir: 解压目标目录，默认为临时目录
        
    Returns:
        (成功与否, 解压目录或错误信息)
    """
    if dest_dir is None:
        dest_dir = tempfile.mkdtemp(prefix='modguard_')
        
    ext = Path(archive_path).suffix.lower()
    
    try:
        if ext == '.zip':
            import zipfile
            with zipfile.ZipFile(archive_path, 'r') as zf:
                zf.extractall(dest_dir)
                
        elif ext == '.7z':
            try:
                import py7zr
                with py7zr.SevenZipFile(archive_path, 'r') as sz:
                    sz.extractall(dest_dir)
            except ImportError:
                return False, "需要安装 py7zr: pip install py7zr"
                
        elif ext == '.rar':
            try:
                import rarfile
                with rarfile.RarFile(archive_path, 'r') as rf:
                    rf.extractall(dest_dir)
            except ImportError:
                return False, "需要安装 rarfile: pip install rarfile"
                
        else:
            return False, f"不支持的压缩格式: {ext}"
            
        return True, dest_dir
        
    except Exception as e:
        return False, str(e)


def safe_read_text(file_path: str, max_size: int = 1024 * 1024) -> Optional[str]:
    """安全读取文本文件"""
    try:
        size = os.path.getsize(file_path)
        if size > max_size:
            return None
            
        # 尝试检测编码
        try:
            import chardet
            with open(file_path, 'rb') as f:
                raw = f.read()
                detected = chardet.detect(raw)
                encoding = detected.get('encoding', 'utf-8')
        except ImportError:
            encoding = 'utf-8'
            
        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
            return f.read()
            
    except Exception:
        return None


def find_files_by_pattern(
    root_dir: str, 
    patterns: List[str],
    recursive: bool = True
) -> List[Path]:
    """按模式查找文件"""
    root = Path(root_dir)
    found = []
    
    for pattern in patterns:
        if recursive:
            found.extend(root.rglob(pattern))
        else:
            found.extend(root.glob(pattern))
            
    return list(set(found))
