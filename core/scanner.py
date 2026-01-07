"""
ModGuard 核心扫描器
整合 YARA 规则扫描和 IL 分析
"""
import os
import time
import zipfile
import tempfile
import shutil
from pathlib import Path
from typing import List, Optional, Callable, Dict
from dataclasses import dataclass

# 可选的压缩格式支持
try:
    import py7zr
    HAS_7Z = True
except ImportError:
    HAS_7Z = False

try:
    import rarfile
    HAS_RAR = True
except ImportError:
    HAS_RAR = False

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import SCAN_CONFIG, RULES_DIR
from .yara_engine import YaraEngine, YaraMatch
from .il_analyzer import ILAnalyzer, ILFinding
from .report import ScanReport, ThreatItem, ScanStatistics


@dataclass
class ScanProgress:
    """扫描进度"""
    current_file: str
    current_index: int
    total_files: int
    phase: str  # 'collecting', 'yara_scan', 'il_analysis', 'finalizing'
    
    @property
    def percentage(self) -> float:
        if self.total_files == 0:
            return 0
        return (self.current_index / self.total_files) * 100


class ModScanner:
    """
    Mod 安全扫描器
    
    整合多种扫描引擎，提供统一的扫描接口
    """
    
    def __init__(self, rules_dir: Path = None):
        self.rules_dir = rules_dir or RULES_DIR
        
        # 初始化引擎
        self.yara_engine = YaraEngine(self.rules_dir)
        self.il_analyzer = ILAnalyzer()
        
        # 状态
        self.is_scanning = False
        self.should_stop = False
        
    def initialize(self) -> bool:
        """初始化扫描器"""
        # 加载 YARA 规则
        yara_ok = self.yara_engine.load_rules()
        return yara_ok
    
    def scan_file(self, file_path: str) -> Dict:
        """
        扫描单个文件（供 GUI 使用）
        
        Args:
            file_path: 文件路径
            
        Returns:
            扫描结果字典
        """
        result = {
            'file': file_path,
            'risk_score': 0,
            'yara_matches': [],
            'il_findings': [],
        }
        
        path = Path(file_path)
        if not path.exists():
            result['error'] = '文件不存在'
            return result
            
        # YARA 扫描
        if self.yara_engine.compiled_rules:
            matches = self.yara_engine.scan_file(path)
            for match in matches:
                result['yara_matches'].append({
                    'rule': match.rule_name,
                    'severity': match.severity,
                    'category': match.category,
                    'description': match.description,
                })
                # 计算风险分
                if match.severity == 'critical':
                    result['risk_score'] += 40
                elif match.severity == 'high':
                    result['risk_score'] += 25
                elif match.severity == 'medium':
                    result['risk_score'] += 15
                elif match.severity == 'low':
                    result['risk_score'] += 5
                    
        # IL 分析
        if path.suffix.lower() in ['.dll', '.exe']:
            findings = self.il_analyzer.analyze_file(path)
            for finding in findings:
                result['il_findings'].append({
                    'api': finding.api_name,
                    'category': finding.category.value,
                    'severity': finding.severity,
                    'description': finding.description,
                    'context': finding.context,
                    'mitigated': finding.mitigated,
                })
                # 计算风险分（已缓解的权重降低）
                multiplier = 0.3 if finding.mitigated else 1.0
                if finding.severity == 'critical':
                    result['risk_score'] += int(35 * multiplier)
                elif finding.severity == 'high':
                    result['risk_score'] += int(20 * multiplier)
                elif finding.severity == 'medium':
                    result['risk_score'] += int(10 * multiplier)
                elif finding.severity == 'low':
                    result['risk_score'] += int(3 * multiplier)
        
        # 压缩文件处理 - 解压并扫描内部文件
        elif path.suffix.lower() in ['.zip', '.7z', '.rar']:
            archive_results = self._scan_archive(path)
            result['archive_contents'] = archive_results
            # 累加压缩包内文件的风险分
            for ar in archive_results:
                result['risk_score'] += ar.get('risk_score', 0)
                result['yara_matches'].extend(ar.get('yara_matches', []))
                result['il_findings'].extend(ar.get('il_findings', []))
                    
        # 限制最高分
        result['risk_score'] = min(result['risk_score'], 100)
        
        return result
    
    def scan(
        self,
        target_path: str,
        progress_callback: Callable[[ScanProgress], None] = None,
        enable_yara: bool = True,
        enable_il: bool = True,
    ) -> ScanReport:
        """
        执行完整扫描
        
        Args:
            target_path: 扫描目标路径
            progress_callback: 进度回调函数
            enable_yara: 是否启用 YARA 扫描
            enable_il: 是否启用 IL 分析
            
        Returns:
            ScanReport: 扫描报告
        """
        self.is_scanning = True
        self.should_stop = False
        start_time = time.time()
        
        target = Path(target_path)
        report = ScanReport(target_path=str(target))
        
        # 收集文件
        self._update_progress(progress_callback, "collecting", "正在收集文件...", 0, 1)
        files_to_scan = self._collect_files(target)
        
        total_files = len(files_to_scan)
        report.statistics.total_files = total_files
        
        # 分类文件
        dotnet_files = [f for f in files_to_scan if f.suffix.lower() in ['.dll', '.exe']]
        script_files = [f for f in files_to_scan if f.suffix.lower() not in ['.dll', '.exe']]
        
        report.statistics.dotnet_files = len(dotnet_files)
        report.statistics.script_files = len(script_files)
        
        # === Phase 1: YARA 扫描 ===
        if enable_yara and self.yara_engine.compiled_rules:
            yara_threats = self._run_yara_scan(
                files_to_scan, 
                progress_callback
            )
            report.add_threats(yara_threats)
            
        if self.should_stop:
            return report
            
        # === Phase 2: IL 分析 ===
        if enable_il and dotnet_files:
            il_threats = self._run_il_analysis(
                dotnet_files,
                progress_callback,
                offset=len(script_files)  # 进度偏移
            )
            report.add_threats(il_threats)
        
        # 完成
        end_time = time.time()
        report.statistics.scan_duration_seconds = end_time - start_time
        report.statistics.scanned_files = total_files
        
        # 生成建议
        report.generate_recommendations()
        
        self.is_scanning = False
        return report
    
    def _collect_files(self, target: Path) -> List[Path]:
        """收集要扫描的文件"""
        files = []
        
        if target.is_file():
            return [target]
            
        config = SCAN_CONFIG
        
        for item in target.rglob('*'):
            # 跳过目录
            if item.is_dir():
                continue
                
            # 检查是否在跳过列表中
            skip = False
            for skip_dir in config.skip_dirs:
                if skip_dir in item.parts:
                    skip = True
                    break
            if skip:
                continue
                
            # 检查扩展名
            if item.suffix.lower() in config.target_extensions:
                # 检查文件大小
                try:
                    if item.stat().st_size <= config.max_file_size:
                        files.append(item)
                except OSError:
                    pass
                    
        return files
    
    def _scan_archive(self, archive_path: Path) -> List[Dict]:
        """
        扫描压缩包内部的文件（支持 zip, 7z, rar）
        
        Args:
            archive_path: 压缩包路径
            
        Returns:
            内部文件的扫描结果列表
        """
        ext = archive_path.suffix.lower()
        
        if ext == '.zip':
            return self._scan_zip_archive(archive_path)
        elif ext == '.7z' and HAS_7Z:
            return self._scan_7z_archive(archive_path)
        elif ext == '.rar' and HAS_RAR:
            return self._scan_rar_archive(archive_path)
        else:
            return []
    
    def _scan_extracted_file(self, extracted_path: Path, display_name: str) -> Optional[Dict]:
        """扫描解压后的单个文件"""
        if not extracted_path.exists():
            return None
            
        try:
            if extracted_path.stat().st_size > 50 * 1024 * 1024:  # 跳过超过 50MB 的文件
                return None
        except:
            return None
            
        file_result = {
            'file': display_name,
            'risk_score': 0,
            'yara_matches': [],
            'il_findings': [],
        }
        
        # YARA 扫描
        if self.yara_engine.compiled_rules:
            matches = self.yara_engine.scan_file(extracted_path)
            for match in matches:
                file_result['yara_matches'].append({
                    'rule': match.rule_name,
                    'severity': match.severity,
                    'category': match.category,
                    'description': match.description,
                })
                if match.severity == 'critical':
                    file_result['risk_score'] += 40
                elif match.severity == 'high':
                    file_result['risk_score'] += 25
                elif match.severity == 'medium':
                    file_result['risk_score'] += 15
                elif match.severity == 'low':
                    file_result['risk_score'] += 5
        
        # IL 分析
        if extracted_path.suffix.lower() in ['.dll', '.exe']:
            findings = self.il_analyzer.analyze_file(extracted_path)
            for finding in findings:
                file_result['il_findings'].append({
                    'api': finding.api_name,
                    'category': finding.category.value,
                    'severity': finding.severity,
                    'description': finding.description,
                    'context': finding.context,
                    'mitigated': finding.mitigated,
                })
                multiplier = 0.3 if finding.mitigated else 1.0
                if finding.severity == 'critical':
                    file_result['risk_score'] += int(35 * multiplier)
                elif finding.severity == 'high':
                    file_result['risk_score'] += int(20 * multiplier)
                elif finding.severity == 'medium':
                    file_result['risk_score'] += int(10 * multiplier)
                elif finding.severity == 'low':
                    file_result['risk_score'] += int(3 * multiplier)
        
        file_result['risk_score'] = min(file_result['risk_score'], 100)
        
        # 只返回有发现的结果
        if file_result['risk_score'] > 0 or file_result['yara_matches'] or file_result['il_findings']:
            return file_result
        return None
    
    def _scan_zip_archive(self, archive_path: Path) -> List[Dict]:
        """扫描 ZIP 压缩包"""
        results = []
        temp_dir = None
        
        try:
            temp_dir = tempfile.mkdtemp(prefix='modguard_')
            
            with zipfile.ZipFile(archive_path, 'r') as zf:
                for member in zf.namelist():
                    # 安全检查
                    if member.startswith('/') or '..' in member:
                        continue
                    
                    ext = os.path.splitext(member)[1].lower()
                    if ext in ['.dll', '.exe']:
                        try:
                            zf.extract(member, temp_dir)
                            extracted_path = Path(temp_dir) / member
                            
                            result = self._scan_extracted_file(
                                extracted_path, 
                                f"{archive_path.name}/{member}"
                            )
                            if result:
                                results.append(result)
                        except:
                            pass
                            
        except zipfile.BadZipFile:
            pass
        except:
            pass
        finally:
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except:
                    pass
                    
        return results
    
    def _scan_7z_archive(self, archive_path: Path) -> List[Dict]:
        """扫描 7z 压缩包"""
        if not HAS_7Z:
            return []
            
        results = []
        temp_dir = None
        
        try:
            temp_dir = tempfile.mkdtemp(prefix='modguard_')
            
            with py7zr.SevenZipFile(archive_path, 'r') as sz:
                # 获取文件列表
                for member in sz.getnames():
                    ext = os.path.splitext(member)[1].lower()
                    if ext in ['.dll', '.exe']:
                        try:
                            sz.extract(path=temp_dir, targets=[member])
                            extracted_path = Path(temp_dir) / member
                            
                            result = self._scan_extracted_file(
                                extracted_path, 
                                f"{archive_path.name}/{member}"
                            )
                            if result:
                                results.append(result)
                        except:
                            pass
                            
        except:
            pass
        finally:
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except:
                    pass
                    
        return results
    
    def _scan_rar_archive(self, archive_path: Path) -> List[Dict]:
        """扫描 RAR 压缩包"""
        if not HAS_RAR:
            return []
            
        results = []
        temp_dir = None
        
        try:
            temp_dir = tempfile.mkdtemp(prefix='modguard_')
            
            with rarfile.RarFile(archive_path, 'r') as rf:
                for member in rf.namelist():
                    ext = os.path.splitext(member)[1].lower()
                    if ext in ['.dll', '.exe']:
                        try:
                            rf.extract(member, temp_dir)
                            extracted_path = Path(temp_dir) / member
                            
                            result = self._scan_extracted_file(
                                extracted_path, 
                                f"{archive_path.name}/{member}"
                            )
                            if result:
                                results.append(result)
                        except:
                            pass
                            
        except:
            pass
        finally:
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except:
                    pass
                    
        return results
    
    def _run_yara_scan(
        self,
        files: List[Path],
        progress_callback: Callable
    ) -> List[ThreatItem]:
        """执行 YARA 扫描"""
        threats = []
        total = len(files)
        
        for idx, file_path in enumerate(files):
            if self.should_stop:
                break
                
            self._update_progress(
                progress_callback, 
                "yara_scan", 
                file_path.name, 
                idx, 
                total
            )
            
            matches = self.yara_engine.scan_file(file_path)
            
            for match in matches:
                threat = ThreatItem(
                    file_path=str(match.file_path),
                    rule_name=match.rule_name,
                    severity=match.severity,
                    category=match.category,
                    description=match.description,
                    source="yara",
                    details={'matched_strings': match.matched_strings}
                )
                threats.append(threat)
                
        return threats
    
    def _run_il_analysis(
        self,
        dotnet_files: List[Path],
        progress_callback: Callable,
        offset: int = 0
    ) -> List[ThreatItem]:
        """执行 IL 分析"""
        threats = []
        total = len(dotnet_files)
        
        for idx, file_path in enumerate(dotnet_files):
            if self.should_stop:
                break
                
            self._update_progress(
                progress_callback,
                "il_analysis",
                file_path.name,
                idx + offset,
                total + offset
            )
            
            findings = self.il_analyzer.analyze_file(file_path)
            
            for finding in findings:
                # 兼容新版 ILFinding 格式
                threat = ThreatItem(
                    file_path=str(finding.file_path),
                    rule_name=f"IL_{finding.category.name}",
                    severity=finding.severity,
                    category=finding.category.value,
                    description=finding.description,
                    source="il_analyzer",
                    details={
                        'api': finding.api_name, 
                        'context': finding.context,
                        'mitigated': finding.mitigated
                    }
                )
                threats.append(threat)
                
        return threats
    
    def _update_progress(
        self,
        callback: Callable,
        phase: str,
        current_file: str,
        current_index: int,
        total_files: int
    ):
        """更新进度"""
        if callback:
            progress = ScanProgress(
                current_file=current_file,
                current_index=current_index,
                total_files=total_files,
                phase=phase
            )
            callback(progress)
    
    def stop(self):
        """停止扫描"""
        self.should_stop = True
        
    def get_engine_status(self) -> Dict:
        """获取引擎状态"""
        return {
            'yara': self.yara_engine.get_status(),
            'il_analyzer': {
                'available': True,
                'signatures_count': len(self.il_analyzer.signatures),
                'trusted_frameworks': len(self.il_analyzer.TRUSTED_FRAMEWORKS),
            }
        }


# === 向后兼容旧版 API ===
class ScannerEngine:
    """兼容旧版 API 的包装类"""
    
    def __init__(self, rules_path):
        self.rules_path = rules_path
        self._scanner = ModScanner(Path(rules_path).parent)
        self._scanner.initialize()
        self.rules = self._scanner.yara_engine.compiled_rules
        
    def scan_directory(self, target_path, callback=None):
        """兼容旧版扫描接口"""
        def progress_adapter(progress):
            if callback:
                callback(progress.current_file, progress.current_index, progress.total_files)
        
        report = self._scanner.scan(target_path, progress_callback=progress_adapter)
        
        # 转换为旧格式
        results = []
        for threat in report.threats:
            results.append({
                "file": threat.file_path,
                "rule": threat.rule_name,
                "severity": threat.severity,
                "desc": threat.description
            })
        return results


# === 便捷函数 ===
def quick_scan(target_path: str) -> ScanReport:
    """快速扫描"""
    scanner = ModScanner()
    scanner.initialize()
    return scanner.scan(target_path)