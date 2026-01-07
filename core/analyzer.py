"""
行为分析器
用于高级行为模式检测
"""
from dataclasses import dataclass
from typing import List, Dict, Optional
from pathlib import Path
from enum import Enum


class BehaviorType(Enum):
    """行为类型"""
    FILE_ACCESS = "file_access"
    NETWORK_COMM = "network_communication"
    PROCESS_EXEC = "process_execution"
    REGISTRY_OP = "registry_operation"
    CRYPTO_OP = "cryptographic_operation"
    DATA_COLLECT = "data_collection"


@dataclass
class BehaviorPattern:
    """行为模式"""
    behavior_type: BehaviorType
    description: str
    indicators: List[str]
    severity: str
    

@dataclass
class AnalysisResult:
    """分析结果"""
    file_path: Path
    behaviors: List[BehaviorPattern]
    risk_score: int
    summary: str
    

class BehaviorAnalyzer:
    """
    行为分析器
    
    通过组合多个特征来判断整体行为意图
    """
    
    def __init__(self):
        self.patterns = self._init_patterns()
        
    def _init_patterns(self) -> List[BehaviorPattern]:
        """初始化行为模式"""
        return [
            BehaviorPattern(
                behavior_type=BehaviorType.DATA_COLLECT,
                description="收集Steam账号信息并外传",
                indicators=[
                    "ssfn", "loginusers", "config.vdf",
                    "http", "webhook", "upload"
                ],
                severity="critical"
            ),
            BehaviorPattern(
                behavior_type=BehaviorType.PROCESS_EXEC,
                description="下载并执行外部程序",
                indicators=[
                    "download", "http", "exe",
                    "process.start", "shell"
                ],
                severity="critical"
            ),
            BehaviorPattern(
                behavior_type=BehaviorType.CRYPTO_OP,
                description="加密本地文件(勒索软件特征)",
                indicators=[
                    "encrypt", "aes", "crypto",
                    "getfiles", "directory"
                ],
                severity="critical"
            ),
        ]
        
    def analyze_file(self, file_path: Path, content: str) -> AnalysisResult:
        """分析单个文件"""
        content_lower = content.lower()
        detected_behaviors = []
        
        for pattern in self.patterns:
            matches = sum(1 for ind in pattern.indicators if ind in content_lower)
            threshold = len(pattern.indicators) * 0.5
            
            if matches >= threshold:
                detected_behaviors.append(pattern)
                
        # 计算风险分
        risk_score = self._calculate_risk(detected_behaviors)
        
        # 生成摘要
        summary = self._generate_summary(detected_behaviors)
        
        return AnalysisResult(
            file_path=file_path,
            behaviors=detected_behaviors,
            risk_score=risk_score,
            summary=summary
        )
        
    def _calculate_risk(self, behaviors: List[BehaviorPattern]) -> int:
        """计算风险分"""
        if not behaviors:
            return 0
            
        weights = {
            'critical': 40,
            'high': 25,
            'medium': 10,
            'low': 3,
        }
        
        score = sum(weights.get(b.severity, 5) for b in behaviors)
        return min(100, score)
        
    def _generate_summary(self, behaviors: List[BehaviorPattern]) -> str:
        """生成摘要"""
        if not behaviors:
            return "未发现可疑行为模式"
            
        descriptions = [b.description for b in behaviors]
        return "检测到: " + "; ".join(descriptions)
