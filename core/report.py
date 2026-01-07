"""
扫描报告生成模块
"""
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum


class ThreatSeverity(Enum):
    """威胁等级"""
    CRITICAL = "critical"   # 🔴 确认恶意
    HIGH = "high"           # 🟠 高度可疑
    MEDIUM = "medium"       # 🟡 敏感行为
    LOW = "low"             # 🟢 提示信息
    INFO = "info"           # ⚪ 仅供参考
    
    @property
    def emoji(self) -> str:
        return {
            "critical": "🚫",
            "high": "🔴",
            "medium": "🟡",
            "low": "🟢",
            "info": "ℹ️",
        }.get(self.value, "❓")
    
    @property
    def display_name(self) -> str:
        return {
            "critical": "严重威胁",
            "high": "高危",
            "medium": "敏感",
            "low": "低风险",
            "info": "信息",
        }.get(self.value, "未知")


@dataclass
class ThreatItem:
    """单个威胁项"""
    file_path: str
    rule_name: str
    severity: str
    category: str
    description: str
    source: str  # 'yara' 或 'il_analyzer'
    details: Dict = field(default_factory=dict)
    
    @property
    def severity_enum(self) -> ThreatSeverity:
        try:
            return ThreatSeverity(self.severity.lower())
        except ValueError:
            return ThreatSeverity.INFO
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ScanStatistics:
    """扫描统计"""
    total_files: int = 0
    scanned_files: int = 0
    skipped_files: int = 0
    dotnet_files: int = 0
    script_files: int = 0
    scan_duration_seconds: float = 0.0
    

@dataclass
class ScanReport:
    """完整扫描报告"""
    # 基本信息
    scan_id: str = ""
    scan_time: str = ""
    target_path: str = ""
    
    # 统计信息
    statistics: ScanStatistics = field(default_factory=ScanStatistics)
    
    # 威胁列表
    threats: List[ThreatItem] = field(default_factory=list)
    
    # 风险评分 (0-100)
    risk_score: int = 0
    
    # 建议
    recommendations: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.scan_id:
            self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        if not self.scan_time:
            self.scan_time = datetime.now().isoformat()
    
    def add_threat(self, threat: ThreatItem):
        """添加威胁"""
        self.threats.append(threat)
        self._recalculate_risk_score()
        
    def add_threats(self, threats: List[ThreatItem]):
        """批量添加威胁"""
        self.threats.extend(threats)
        self._recalculate_risk_score()
        
    def _recalculate_risk_score(self):
        """重新计算风险评分"""
        if not self.threats:
            self.risk_score = 0
            return
            
        # 权重
        weights = {
            'critical': 40,
            'high': 25,
            'medium': 10,
            'low': 3,
            'info': 1,
        }
        
        score = 0
        for threat in self.threats:
            severity = threat.severity.lower()
            score += weights.get(severity, 1)
            
        # 上限100
        self.risk_score = min(100, score)
        
    def generate_recommendations(self):
        """生成建议"""
        self.recommendations = []
        
        # 统计各等级威胁数
        severity_counts = {}
        for threat in self.threats:
            sev = threat.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # 根据威胁生成建议
        if severity_counts.get('critical', 0) > 0:
            self.recommendations.append(
                "⛔ 发现严重威胁！强烈建议不要使用此 Mod，可能存在恶意行为。"
            )
            
        if severity_counts.get('high', 0) > 0:
            self.recommendations.append(
                "🔴 发现高危行为，建议仔细审查相关文件后再决定是否使用。"
            )
            
        if severity_counts.get('medium', 0) > 0:
            self.recommendations.append(
                "🟡 发现敏感权限调用，这些功能在某些 Mod 中可能是正常的，请根据 Mod 用途判断。"
            )
            
        if not self.threats:
            self.recommendations.append(
                "✅ 未检测出明显可疑行为，但检测结果仅供参考，使用时仍需保持警惕。"
            )
            
        # 通用建议
        self.recommendations.append(
            "💡 建议：从官方创意工坊下载 Mod，避免从不明来源获取。"
        )
    
    def get_threat_summary(self) -> Dict:
        """获取威胁摘要"""
        summary = {
            'total': len(self.threats),
            'by_severity': {},
            'by_category': {},
            'by_source': {},
        }
        
        for threat in self.threats:
            sev = threat.severity.lower()
            cat = threat.category
            src = threat.source
            
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1
            summary['by_category'][cat] = summary['by_category'].get(cat, 0) + 1
            summary['by_source'][src] = summary['by_source'].get(src, 0) + 1
            
        return summary
    
    def to_dict(self) -> Dict:
        """转换为字典"""
        return {
            'scan_id': self.scan_id,
            'scan_time': self.scan_time,
            'target_path': self.target_path,
            'risk_score': self.risk_score,
            'statistics': asdict(self.statistics),
            'threat_summary': self.get_threat_summary(),
            'threats': [t.to_dict() for t in self.threats],
            'recommendations': self.recommendations,
        }
    
    def to_json(self, indent: int = 2) -> str:
        """转换为 JSON 字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
    
    def save(self, output_path: Path):
        """保存报告到文件"""
        output_path.write_text(self.to_json(), encoding='utf-8')
        
    @classmethod
    def load(cls, file_path: Path) -> 'ScanReport':
        """从文件加载报告"""
        data = json.loads(file_path.read_text(encoding='utf-8'))
        
        report = cls(
            scan_id=data.get('scan_id', ''),
            scan_time=data.get('scan_time', ''),
            target_path=data.get('target_path', ''),
            risk_score=data.get('risk_score', 0),
            recommendations=data.get('recommendations', []),
        )
        
        # 加载统计
        if 'statistics' in data:
            report.statistics = ScanStatistics(**data['statistics'])
            
        # 加载威胁
        for t_data in data.get('threats', []):
            report.threats.append(ThreatItem(**t_data))
            
        return report


class ReportFormatter:
    """报告格式化器"""
    
    @staticmethod
    def to_text(report: ScanReport) -> str:
        """转换为文本格式"""
        lines = [
            "=" * 60,
            f"ModGuard 扫描报告",
            "=" * 60,
            f"扫描时间: {report.scan_time}",
            f"扫描目标: {report.target_path}",
            f"风险评分: {report.risk_score}/100",
            "",
            "-" * 40,
            "威胁统计",
            "-" * 40,
        ]
        
        summary = report.get_threat_summary()
        for sev, count in summary['by_severity'].items():
            try:
                sev_enum = ThreatSeverity(sev)
                lines.append(f"  {sev_enum.emoji} {sev_enum.display_name}: {count}")
            except ValueError:
                lines.append(f"  {sev}: {count}")
        
        lines.append("")
        lines.append("-" * 40)
        lines.append("详细威胁列表")
        lines.append("-" * 40)
        
        for i, threat in enumerate(report.threats, 1):
            sev_enum = threat.severity_enum
            lines.append(f"\n{i}. {sev_enum.emoji} [{sev_enum.display_name}] {threat.rule_name}")
            lines.append(f"   文件: {threat.file_path}")
            lines.append(f"   说明: {threat.description}")
        
        lines.append("")
        lines.append("-" * 40)
        lines.append("使用建议")
        lines.append("-" * 40)
        
        for rec in report.recommendations:
            lines.append(f"  • {rec}")
            
        lines.append("")
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    @staticmethod
    def to_html(report: ScanReport) -> str:
        """转换为 HTML 格式 (简化版)"""
        # 这里可以扩展为完整的 HTML 模板
        return f"""
        <html>
        <head><title>ModGuard 扫描报告</title></head>
        <body>
        <h1>ModGuard 扫描报告</h1>
        <p>扫描时间: {report.scan_time}</p>
        <p>风险评分: <strong>{report.risk_score}/100</strong></p>
        <p>发现威胁: {len(report.threats)} 个</p>
        </body>
        </html>
        """


class ReportGenerator:
    """报告生成器 - 供 GUI 使用"""
    
    @staticmethod
    def generate_summary(results: List[Dict]) -> Dict:
        """从扫描结果生成摘要"""
        total_files = len(results)
        threat_count = 0
        warning_count = 0
        max_risk_score = 0
        
        for result in results:
            score = result.get('risk_score', 0)
            max_risk_score = max(max_risk_score, score)
            
            if score >= 50:
                threat_count += 1
            elif score >= 30:
                warning_count += 1
                
        # 确定整体威胁等级
        if max_risk_score >= 80:
            overall_level = "危险"
        elif max_risk_score >= 50:
            overall_level = "高风险"
        elif max_risk_score >= 30:
            overall_level = "中等风险"
        elif max_risk_score > 0:
            overall_level = "低风险"
        else:
            overall_level = "未检出风险"
            
        return {
            'total_files': total_files,
            'threat_count': threat_count,
            'warning_count': warning_count,
            'max_risk_score': max_risk_score,
            'overall_threat_level': overall_level,
            'scan_time': datetime.now().isoformat(),
        }
    
    @staticmethod
    def generate_html(results: List[Dict]) -> str:
        """生成 HTML 报告"""
        summary = ReportGenerator.generate_summary(results)
        
        threats_html = ""
        for result in results:
            if result.get('risk_score', 0) > 0:
                filename = Path(result.get('file', 'Unknown')).name
                score = result.get('risk_score', 0)
                
                # 风险级别和颜色
                if score >= 80:
                    color = "#dc3545"
                    level = "🔴 高风险"
                    level_desc = "该文件调用了多项敏感权限，建议谨慎使用"
                elif score >= 50:
                    color = "#fd7e14"
                    level = "🟠 敏感权限"
                    level_desc = "该文件存在敏感的权限调用"
                elif score >= 30:
                    color = "#ffc107"
                    level = "🟡 轻微敏感"
                    level_desc = "该文件有一些敏感行为，请留意"
                else:
                    color = "#17a2b8"
                    level = "🔵 低风险"
                    level_desc = "该文件权限使用较为正常"
                    
                # 收集检测详情
                details = []
                for match in result.get('yara_matches', []):
                    desc = match.get('description', match.get('rule', '未知'))
                    details.append(f"<li>{desc}</li>")
                for finding in result.get('il_findings', []):
                    desc = finding.get('description', finding.get('api', '未知'))
                    details.append(f"<li>{desc}</li>")
                    
                details_html = "<ul>" + "".join(details[:5]) + "</ul>" if details else "<em>无详细信息</em>"
                    
                threats_html += f"""
                <div class="file-card" style="border-left: 4px solid {color};">
                    <div class="file-header">
                        <span class="file-name">{filename}</span>
                        <span class="file-score" style="color: {color};">风险评分: {score}</span>
                    </div>
                    <div class="file-level">{level}</div>
                    <div class="file-desc">{level_desc}</div>
                    <div class="file-details">
                        <strong>检测到的敏感权限/行为:</strong>
                        {details_html}
                    </div>
                </div>
                """
        
        # 生成使用建议
        advice_html = ""
        if summary['max_risk_score'] >= 80:
            advice_html = """
            <div class="advice danger">
                <h3>⚠️ 重要提醒</h3>
                <p>扫描结果显示存在<strong>高风险</strong>的文件，这些文件可能：</p>
                <ul>
                    <li>尝试读取您的 Steam 账号信息</li>
                    <li>收集您的电脑信息并发送到网络</li>
                    <li>执行其他可能影响您账号安全的操作</li>
                </ul>
                <p><strong>建议：</strong>除非您完全信任此Mod的来源，否则建议取消订阅或删除这些文件。</p>
            </div>
            """
        elif summary['max_risk_score'] >= 50:
            advice_html = """
            <div class="advice warning">
                <h3>⚡ 请注意</h3>
                <p>扫描结果显示存在使用<strong>敏感权限</strong>的文件，建议您：</p>
                <ul>
                    <li>确认这些Mod来自可信的创作者</li>
                    <li>查看Mod的评论区是否有其他用户反馈问题</li>
                    <li>如有疑虑，可以暂时取消订阅</li>
                </ul>
            </div>
            """
        elif summary['max_risk_score'] >= 30:
            advice_html = """
            <div class="advice info">
                <h3>💡 提示</h3>
                <p>扫描结果显示部分文件有<strong>轻微敏感</strong>的权限调用，这在某些Mod中可能是正常的。</p>
                <p>如果Mod功能需要网络连接（如多人联机、排行榜等），出现网络相关检测是正常的。</p>
            </div>
            """
        else:
            advice_html = """
            <div class="advice safe">
                <h3>✅ 扫描结果</h3>
                <p>未检测出明显的敏感权限调用。</p>
                <p><em>注意：扫描结果仅供参考，无法保证绝对安全，使用任何Mod时仍需保持警惕。</em></p>
            </div>
            """
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>ModGuard Mod扫描报告</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{ 
            font-family: 'Microsoft YaHei', 'Segoe UI', sans-serif; 
            margin: 0; 
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{ 
            max-width: 900px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 16px; 
            box-shadow: 0 10px 40px rgba(0,0,0,0.2); 
        }}
        h1 {{ 
            color: #2c3e50; 
            text-align: center;
            margin-bottom: 10px;
        }}
        .subtitle {{
            text-align: center;
            color: #666;
            margin-bottom: 30px;
        }}
        .summary {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
            gap: 15px; 
            margin: 20px 0; 
        }}
        .stat-card {{ 
            background: #f8f9fa; 
            padding: 20px; 
            border-radius: 12px; 
            text-align: center;
            transition: transform 0.2s;
        }}
        .stat-card:hover {{ transform: translateY(-2px); }}
        .stat-value {{ font-size: 32px; font-weight: bold; }}
        .stat-label {{ color: #666; font-size: 14px; margin-top: 5px; }}
        
        .advice {{
            padding: 20px;
            border-radius: 12px;
            margin: 25px 0;
        }}
        .advice.danger {{ background: #fee; border-left: 4px solid #dc3545; }}
        .advice.warning {{ background: #fff8e6; border-left: 4px solid #fd7e14; }}
        .advice.info {{ background: #fff9e6; border-left: 4px solid #ffc107; }}
        .advice.safe {{ background: #e8f5e9; border-left: 4px solid #28a745; }}
        .advice h3 {{ margin-top: 0; }}
        
        .file-card {{
            background: #f8f9fa;
            padding: 15px 20px;
            margin: 10px 0;
            border-radius: 8px;
        }}
        .file-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .file-name {{ font-weight: bold; font-size: 16px; }}
        .file-score {{ font-weight: bold; }}
        .file-level {{ margin: 8px 0; }}
        .file-desc {{ color: #666; font-size: 14px; }}
        .file-details {{ margin-top: 10px; font-size: 13px; }}
        .file-details ul {{ margin: 5px 0; padding-left: 20px; }}
        
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #999;
            font-size: 12px;
        }}
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ ModGuard 扫描报告</h1>
    <p class="subtitle">扫描时间: {summary['scan_time'][:19].replace('T', ' ')}</p>
    
    <div class="summary">
        <div class="stat-card">
            <div class="stat-value">{summary['total_files']}</div>
            <div class="stat-label">扫描文件数</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: #dc3545;">{summary['threat_count']}</div>
            <div class="stat-label">高敏感文件</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: #ffc107;">{summary['warning_count']}</div>
            <div class="stat-label">中等敏感</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: {'#dc3545' if summary['max_risk_score'] >= 50 else '#28a745'};">{summary['max_risk_score']}</div>
            <div class="stat-label">最高敏感度</div>
        </div>
    </div>
    
    {advice_html}
    
    <h2>📋 详细检测结果</h2>
    {threats_html if threats_html else '<div class="file-card" style="border-left: 4px solid #28a745; text-align: center;"><p style="color: #28a745; font-size: 18px;">✅ 未检测出敏感权限调用</p></div>'}
    
    <div class="footer">
        <p>此报告由 ModGuard 自动生成 | 检测结果仅供参考，请结合实际情况判断</p>
        <p>建议仅从 Steam 创意工坊等官方渠道下载Mod</p>
    </div>
</div>
</body>
</html>
        """
        
        return html
