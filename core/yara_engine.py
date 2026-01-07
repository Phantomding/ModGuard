"""
YARA 规则引擎
用于静态特征匹配
"""
import os
from pathlib import Path
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("⚠️ yara-python 未安装，静态规则扫描不可用")

from config import RULES_DIR, THREAT_LEVEL


@dataclass
class YaraMatch:
    """YARA 匹配结果"""
    rule_name: str
    file_path: Path
    severity: str
    category: str
    description: str
    matched_strings: List[str]
    
    def to_dict(self) -> Dict:
        return {
            'rule': self.rule_name,
            'file': str(self.file_path),
            'severity': self.severity,
            'category': self.category,
            'description': self.description,
            'matches': self.matched_strings,
        }


class YaraEngine:
    """YARA 规则扫描引擎"""
    
    def __init__(self, rules_dir: Path = None):
        self.rules_dir = rules_dir or RULES_DIR
        self.compiled_rules = None
        self.rule_count = 0
        self.last_error: Optional[str] = None
        
    def load_rules(self) -> bool:
        """加载并编译所有规则"""
        if not YARA_AVAILABLE:
            self.last_error = "yara-python 未安装"
            return False
            
        if not self.rules_dir.exists():
            self.last_error = f"规则目录不存在: {self.rules_dir}"
            return False
        
        # 收集所有 .yar 文件
        rule_files = {}
        for yar_file in self.rules_dir.glob("*.yar"):
            namespace = yar_file.stem  # 用文件名作为命名空间
            rule_files[namespace] = str(yar_file)
            
        if not rule_files:
            self.last_error = "未找到任何 .yar 规则文件"
            return False
            
        try:
            self.compiled_rules = yara.compile(filepaths=rule_files)
            self.rule_count = len(rule_files)
            return True
        except yara.SyntaxError as e:
            self.last_error = f"规则语法错误: {e}"
            return False
        except Exception as e:
            self.last_error = f"规则加载失败: {e}"
            return False
    
    def scan_file(self, file_path: Path) -> List[YaraMatch]:
        """扫描单个文件"""
        if not self.compiled_rules:
            return []
            
        matches = []
        try:
            yara_matches = self.compiled_rules.match(str(file_path))
            
            for match in yara_matches:
                # 提取匹配的字符串
                matched_strs = []
                for string_match in match.strings:
                    # yara-python 4.x 格式
                    for instance in string_match.instances:
                        try:
                            matched_strs.append(instance.matched_data.decode('utf-8', errors='replace')[:100])
                        except:
                            matched_strs.append(str(instance.matched_data)[:100])
                
                yara_match = YaraMatch(
                    rule_name=match.rule,
                    file_path=file_path,
                    severity=match.meta.get('severity', 'unknown'),
                    category=match.meta.get('category', 'General'),
                    description=match.meta.get('description', '无描述'),
                    matched_strings=matched_strs[:5]  # 最多保留5个
                )
                matches.append(yara_match)
                
        except yara.Error as e:
            # 文件可能被占用或无法读取
            pass
        except Exception as e:
            pass
            
        return matches
    
    def scan_directory(
        self, 
        target_dir: Path, 
        extensions: List[str] = None,
        progress_callback: Callable[[str, int, int], None] = None
    ) -> List[YaraMatch]:
        """扫描整个目录"""
        if not self.compiled_rules:
            if not self.load_rules():
                return []
        
        # 默认扫描的扩展名
        if extensions is None:
            extensions = ['.lua', '.py', '.dll', '.exe', '.js', '.vbs', '.bat', '.ps1']
        
        # 收集文件
        files_to_scan = []
        for ext in extensions:
            files_to_scan.extend(target_dir.rglob(f"*{ext}"))
        
        total = len(files_to_scan)
        all_matches = []
        
        for idx, file_path in enumerate(files_to_scan):
            if progress_callback:
                progress_callback(file_path.name, idx, total)
                
            matches = self.scan_file(file_path)
            all_matches.extend(matches)
            
        return all_matches
    
    def scan_data(self, data: bytes, identifier: str = "memory") -> List[YaraMatch]:
        """扫描内存数据"""
        if not self.compiled_rules:
            return []
            
        matches = []
        try:
            yara_matches = self.compiled_rules.match(data=data)
            
            for match in yara_matches:
                yara_match = YaraMatch(
                    rule_name=match.rule,
                    file_path=Path(identifier),
                    severity=match.meta.get('severity', 'unknown'),
                    category=match.meta.get('category', 'General'),
                    description=match.meta.get('description', '无描述'),
                    matched_strings=[]
                )
                matches.append(yara_match)
                
        except Exception:
            pass
            
        return matches
    
    def get_status(self) -> Dict:
        """获取引擎状态"""
        return {
            'available': YARA_AVAILABLE,
            'loaded': self.compiled_rules is not None,
            'rule_count': self.rule_count,
            'rules_dir': str(self.rules_dir),
            'last_error': self.last_error,
        }
