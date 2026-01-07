"""
ModGuard - 主窗口模块 v2.1
响应式布局优化版
"""

import os
import json
from datetime import datetime
from typing import Optional, List, Dict, Any

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QTabWidget, QPushButton, QLabel, QLineEdit, QTextEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QFileDialog, QMessageBox, QGroupBox, QFrame, QSplitter,
    QSizePolicy, QScrollArea, QSpacerItem, QComboBox, QCheckBox,
    QToolTip, QAbstractItemView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer, QMimeData
from PyQt6.QtGui import QFont, QColor, QIcon, QPalette, QAction, QDragEnterEvent, QDropEvent

from core.scanner import ModScanner
from core.steam_finder import SteamFinder
from core.report import ReportGenerator
from config import ScanConfig, ThreatLevel


class ScanWorker(QThread):
    """扫描工作线程"""
    progress = pyqtSignal(int, str)  # 进度值, 状态消息
    file_scanned = pyqtSignal(str, dict)  # 文件路径, 扫描结果
    finished = pyqtSignal(dict)  # 完整扫描报告
    error = pyqtSignal(str)  # 错误消息
    
    def __init__(self, paths: List[str], config: ScanConfig):
        super().__init__()
        self.paths = paths
        self.config = config
        self._is_cancelled = False
        
    def cancel(self):
        self._is_cancelled = True
        
    def run(self):
        try:
            scanner = ModScanner(self.config)
            all_files = []
            
            # 收集所有文件
            self.progress.emit(0, "正在收集文件...")
            for path in self.paths:
                if self._is_cancelled:
                    return
                if os.path.isfile(path):
                    all_files.append(path)
                elif os.path.isdir(path):
                    for root, dirs, files in os.walk(path):
                        for f in files:
                            if f.lower().endswith(('.dll', '.exe', '.zip', '.rar', '.7z')):
                                all_files.append(os.path.join(root, f))
            
            if not all_files:
                self.error.emit("未找到可扫描的文件")
                return
                
            total = len(all_files)
            results = []
            
            for i, file_path in enumerate(all_files):
                if self._is_cancelled:
                    return
                    
                progress = int((i / total) * 100)
                filename = os.path.basename(file_path)
                self.progress.emit(progress, f"正在扫描: {filename}")
                
                try:
                    result = scanner.scan_file(file_path)
                    results.append(result)
                    self.file_scanned.emit(file_path, result)
                except Exception as e:
                    self.file_scanned.emit(file_path, {
                        'file': file_path,
                        'error': str(e),
                        'risk_score': 0
                    })
            
            self.progress.emit(100, "扫描完成")
            
            # 生成报告
            report = ReportGenerator.generate_summary(results)
            self.finished.emit(report)
            
        except Exception as e:
            self.error.emit(f"扫描过程中发生错误: {str(e)}")


class DropZone(QFrame):
    """文件拖放区域组件"""
    files_dropped = pyqtSignal(list)  # 拖放的文件路径列表
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setup_ui()
        self._is_dragging = False
        
    def setup_ui(self):
        """设置UI"""
        self.setMinimumHeight(120)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # 图标
        self.icon_label = QLabel("📂")
        self.icon_label.setStyleSheet("font-size: 36px;")
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # 提示文字
        self.text_label = QLabel("将文件或文件夹拖放到此处进行扫描")
        self.text_label.setStyleSheet("font-size: 14px; color: #666;")
        self.text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # 支持格式提示
        self.hint_label = QLabel("支持格式: .dll, .exe, .zip, .rar, .7z 或文件夹")
        self.hint_label.setStyleSheet("font-size: 11px; color: #999;")
        self.hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(self.icon_label)
        layout.addWidget(self.text_label)
        layout.addWidget(self.hint_label)
        
        self.update_style(False)
        
    def update_style(self, is_dragging: bool):
        """更新样式"""
        if is_dragging:
            self.setStyleSheet("""
                DropZone {
                    background-color: #e8f4fd;
                    border: 2px dashed #3498db;
                    border-radius: 12px;
                }
            """)
            self.icon_label.setText("📥")
            self.text_label.setText("释放以开始扫描")
            self.text_label.setStyleSheet("font-size: 14px; color: #3498db; font-weight: bold;")
        else:
            self.setStyleSheet("""
                DropZone {
                    background-color: #f8f9fa;
                    border: 2px dashed #ccc;
                    border-radius: 12px;
                }
                DropZone:hover {
                    border-color: #3498db;
                    background-color: #f0f7fc;
                }
            """)
            self.icon_label.setText("📂")
            self.text_label.setText("将文件或文件夹拖放到此处进行扫描")
            self.text_label.setStyleSheet("font-size: 14px; color: #666;")
            
    def dragEnterEvent(self, event: QDragEnterEvent):
        """拖入事件"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.update_style(True)
        else:
            event.ignore()
            
    def dragLeaveEvent(self, event):
        """拖出事件"""
        self.update_style(False)
        
    def dropEvent(self, event: QDropEvent):
        """放下事件"""
        self.update_style(False)
        
        if event.mimeData().hasUrls():
            paths = []
            for url in event.mimeData().urls():
                path = url.toLocalFile()
                if path:
                    # 检查是否是支持的文件类型或文件夹
                    if os.path.isdir(path):
                        paths.append(path)
                    elif os.path.isfile(path):
                        ext = os.path.splitext(path)[1].lower()
                        if ext in ('.dll', '.exe', '.zip', '.rar', '.7z'):
                            paths.append(path)
                            
            if paths:
                self.files_dropped.emit(paths)
                event.acceptProposedAction()
            else:
                event.ignore()
        else:
            event.ignore()


class ResponsiveTable(QTableWidget):
    """响应式表格组件"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_table()
        
    def setup_table(self):
        """设置表格基本属性"""
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(True)
        self.verticalHeader().setDefaultSectionSize(45)
        
        # 设置尺寸策略 - 让表格可以扩展
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMinimumHeight(200)
        
        # 表头基本设置
        header = self.horizontalHeader()
        header.setStretchLastSection(False)  # 关闭自动拉伸，使用自定义策略
        
    def configure_columns(self):
        """配置列宽策略 - 在设置完列后调用"""
        if self.columnCount() == 0:
            return
            
        header = self.horizontalHeader()
        col_count = self.columnCount()
        
        # 检查表头来区分不同表格
        header_1_text = self.horizontalHeaderItem(1).text() if self.horizontalHeaderItem(1) else ""
        
        if col_count == 4 and "Mod" in header_1_text:
            # Steam游戏表格: 游戏名称, Mod数量, Mod位置, 操作
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)         # 游戏名称 - 自动拉伸
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents) # Mod数量 - 内容自适应
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)         # Mod位置 - 自动拉伸
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)           # 操作 - 固定宽度
            self.setColumnWidth(3, 150)  # 150px 足够放两个按钮
            
        elif col_count == 4:
            # 扫描结果表格: 文件名, 风险分, 风险等级, 详情
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)         # 文件名 - 自动拉伸
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents) # 风险分 - 内容自适应
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents) # 风险等级 - 内容自适应
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)         # 详情 - 自动拉伸
            
        else:
            # 其他表格 - 平均拉伸
            for i in range(col_count):
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)


class RiskIndicator(QFrame):
    """敏感度指示器组件"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)
        
        # 标题
        self.title_label = QLabel("风险评分")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet("font-size: 14px; color: #666;")
        
        # 分数显示
        self.score_label = QLabel("--")
        self.score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.score_label.setStyleSheet("""
            font-size: 48px;
            font-weight: bold;
            color: #28a745;
        """)
        
        # 状态文字
        self.status_label = QLabel("等待扫描")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("font-size: 12px; color: #888;")
        
        layout.addWidget(self.title_label)
        layout.addWidget(self.score_label)
        layout.addWidget(self.status_label)
        
        # 设置尺寸策略
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(120)
        
    def set_score(self, score: int, threat_level: str = ""):
        """设置风险分数"""
        self.score_label.setText(str(score))
        
        # 根据分数设置颜色和状态
        if score >= 80:
            color = "#dc3545"  # 红色
            status = "高风险"
        elif score >= 50:
            color = "#fd7e14"  # 橙色
            status = "中高风险"
        elif score >= 30:
            color = "#ffc107"  # 黄色
            status = "中等风险"
        elif score > 0:
            color = "#17a2b8"  # 蓝色
            status = "低风险"
        else:
            color = "#28a745"  # 绿色
            status = "未检出风险"
            
        self.score_label.setStyleSheet(f"""
            font-size: 48px;
            font-weight: bold;
            color: {color};
        """)
        self.status_label.setText(threat_level or status)
        self.status_label.setStyleSheet(f"font-size: 12px; color: {color};")


class StatCard(QFrame):
    """统计卡片组件"""
    
    def __init__(self, title: str, value: str = "0", color: str = "#333", parent=None):
        super().__init__(parent)
        self.color = color
        self.setup_ui(title, value)
        
    def setup_ui(self, title: str, value: str):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 10, 15, 10)
        layout.setSpacing(5)
        
        self.value_label = QLabel(value)
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.value_label.setStyleSheet(f"""
            font-size: 28px;
            font-weight: bold;
            color: {self.color};
        """)
        
        self.title_label = QLabel(title)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet("font-size: 12px; color: #666;")
        
        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)
        
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            StatCard {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 8px;
            }
        """)
        
        # 设置尺寸策略
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumWidth(100)
        self.setMinimumHeight(80)
        
    def set_value(self, value: str):
        self.value_label.setText(value)


class MainWindow(QMainWindow):
    """主窗口 - 响应式布局版"""
    
    def __init__(self):
        super().__init__()
        self.config = ScanConfig()
        self.scan_worker = None
        self.scan_results = []
        self.steam_finder = SteamFinder()
        
        self.setup_ui()
        self.load_styles()
        self.connect_signals()
        
    def setup_ui(self):
        """设置UI"""
        self.setWindowTitle("ModGuard - Steam Mod 安全检测工具 v2.1")
        self.setMinimumSize(900, 600)
        self.resize(1200, 800)
        
        # 中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # 标题栏
        self.create_header(main_layout)
        
        # 标签页
        self.tab_widget = QTabWidget()
        self.tab_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        main_layout.addWidget(self.tab_widget, 1)  # stretch factor = 1
        
        # 创建各标签页
        self.create_quick_scan_tab()
        self.create_steam_tab()
        self.create_results_tab()
        
        # 状态栏
        self.create_status_bar()
        
    def create_header(self, parent_layout):
        """创建顶部标题栏"""
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background-color: #2c3e50;
                border-radius: 8px;
            }
        """)
        header.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        header.setMinimumHeight(60)
        
        layout = QHBoxLayout(header)
        layout.setContentsMargins(20, 10, 20, 10)
        
        # Logo 和标题
        title = QLabel("🛡️ ModGuard")
        title.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: white;
        """)
        
        subtitle = QLabel("Steam Mod 安全检测工具")
        subtitle.setStyleSheet("font-size: 14px; color: #bdc3c7;")
        
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addStretch()
        
        # 版本信息
        version = QLabel("v2.1")
        version.setStyleSheet("font-size: 12px; color: #95a5a6;")
        layout.addWidget(version)
        
        parent_layout.addWidget(header)
        
    def create_quick_scan_tab(self):
        """创建快速扫描标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # === 顶部：拖放区域 + 文件选择 ===
        top_widget = QWidget()
        top_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(10)
        
        # 拖放区域
        self.drop_zone = DropZone()
        self.drop_zone.files_dropped.connect(self.on_files_dropped)
        top_layout.addWidget(self.drop_zone)
        
        # 文件选择区域
        select_group = QGroupBox("或手动选择扫描目标")
        select_group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        select_layout = QHBoxLayout(select_group)
        select_layout.setSpacing(10)
        
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("选择文件或文件夹进行扫描...")
        self.path_input.setMinimumHeight(36)
        self.path_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        
        btn_file = QPushButton("📄 选择文件")
        btn_file.setMinimumHeight(36)
        btn_file.setMinimumWidth(100)
        btn_file.clicked.connect(self.select_file)
        
        btn_folder = QPushButton("📁 选择文件夹")
        btn_folder.setMinimumHeight(36)
        btn_folder.setMinimumWidth(100)
        btn_folder.clicked.connect(self.select_folder)
        
        select_layout.addWidget(self.path_input, 1)
        select_layout.addWidget(btn_file)
        select_layout.addWidget(btn_folder)
        
        top_layout.addWidget(select_group)
        layout.addWidget(top_widget)
        
        # === 中部：使用 QSplitter 分割 ===
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
        # 左侧：扫描控制面板
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(15)
        
        # 风险指示器
        self.risk_indicator = RiskIndicator()
        left_layout.addWidget(self.risk_indicator)
        
        # 统计卡片
        stats_widget = QWidget()
        stats_layout = QGridLayout(stats_widget)
        stats_layout.setSpacing(10)
        
        self.stat_total = StatCard("已扫描文件", "0", "#333")
        self.stat_threats = StatCard("高危行为", "0", "#dc3545")
        self.stat_warnings = StatCard("敏感权限", "0", "#ffc107")
        self.stat_safe = StatCard("正常文件", "0", "#28a745")
        
        stats_layout.addWidget(self.stat_total, 0, 0)
        stats_layout.addWidget(self.stat_threats, 0, 1)
        stats_layout.addWidget(self.stat_warnings, 1, 0)
        stats_layout.addWidget(self.stat_safe, 1, 1)
        
        left_layout.addWidget(stats_widget)
        
        # 扫描按钮
        self.btn_scan = QPushButton("🔍 开始扫描")
        self.btn_scan.setMinimumHeight(50)
        self.btn_scan.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                font-size: 16px;
                font-weight: bold;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        self.btn_scan.clicked.connect(self.start_scan)
        left_layout.addWidget(self.btn_scan)
        
        # 取消按钮
        self.btn_cancel = QPushButton("⏹️ 取消扫描")
        self.btn_cancel.setMinimumHeight(40)
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setStyleSheet("""
            QPushButton {
                background-color: #e74c3c;
                color: white;
                font-size: 14px;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #c0392b;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        self.btn_cancel.clicked.connect(self.cancel_scan)
        left_layout.addWidget(self.btn_cancel)
        
        left_layout.addStretch()
        
        # 右侧：实时日志
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        log_label = QLabel("📋 扫描日志")
        log_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #333;")
        right_layout.addWidget(log_label)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                border: 1px solid #333;
                border-radius: 4px;
            }
        """)
        self.log_text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        right_layout.addWidget(self.log_text, 1)
        
        # 添加到分割器
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([300, 500])  # 初始比例
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        
        layout.addWidget(splitter, 1)
        
        # === 底部：进度条 ===
        progress_widget = QWidget()
        progress_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        progress_layout = QHBoxLayout(progress_widget)
        progress_layout.setContentsMargins(0, 0, 0, 0)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(25)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 4px;
                text-align: center;
                background-color: #f0f0f0;
            }
            QProgressBar::chunk {
                background-color: #3498db;
                border-radius: 3px;
            }
        """)
        
        self.progress_label = QLabel("就绪")
        self.progress_label.setMinimumWidth(150)
        self.progress_label.setStyleSheet("color: #666;")
        
        progress_layout.addWidget(self.progress_bar, 1)
        progress_layout.addWidget(self.progress_label)
        
        layout.addWidget(progress_widget)
        
        self.tab_widget.addTab(tab, "🔍 快速扫描")
        
    def create_steam_tab(self):
        """创建Steam游戏标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # Steam 路径显示
        steam_info = QGroupBox("Steam 信息")
        steam_info.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        steam_layout = QHBoxLayout(steam_info)
        
        self.steam_path_label = QLabel("正在检测 Steam 安装路径...")
        self.steam_path_label.setStyleSheet("color: #666;")
        self.steam_path_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        
        btn_refresh = QPushButton("🔄 刷新")
        btn_refresh.setMinimumWidth(80)
        btn_refresh.clicked.connect(self.refresh_steam_games)
        
        steam_layout.addWidget(self.steam_path_label, 1)
        steam_layout.addWidget(btn_refresh)
        
        layout.addWidget(steam_info)
        
        # 游戏列表
        games_group = QGroupBox("已安装的游戏 (仅显示有Mod的游戏)")
        games_group.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        games_layout = QVBoxLayout(games_group)
        
        self.steam_table = ResponsiveTable()
        self.steam_table.setColumnCount(4)
        self.steam_table.setHorizontalHeaderLabels(["游戏名称", "Mod数量", "Mod位置", "操作"])
        self.steam_table.configure_columns()  # 配置列宽策略
        
        games_layout.addWidget(self.steam_table)
        layout.addWidget(games_group, 1)
        
        # 批量操作
        batch_widget = QWidget()
        batch_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        batch_layout = QHBoxLayout(batch_widget)
        batch_layout.setContentsMargins(0, 0, 0, 0)
        
        batch_layout.addStretch()
        
        btn_scan_all = QPushButton("🔍 扫描全部游戏")
        btn_scan_all.setMinimumHeight(40)
        btn_scan_all.setMinimumWidth(150)
        btn_scan_all.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                font-size: 14px;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #219a52;
            }
        """)
        btn_scan_all.clicked.connect(self.scan_all_steam_games)
        batch_layout.addWidget(btn_scan_all)
        
        layout.addWidget(batch_widget)
        
        self.tab_widget.addTab(tab, "🎮 Steam 游戏")
        
        # 延迟加载 Steam 游戏
        QTimer.singleShot(500, self.refresh_steam_games)
        
    def create_results_tab(self):
        """创建扫描结果标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # 使用 QSplitter 分割结果表和详情
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
        # 上部：结果表格
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        table_layout.setContentsMargins(0, 0, 0, 0)
        
        table_header = QHBoxLayout()
        table_label = QLabel("📊 扫描结果")
        table_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["全部", "高危行为", "敏感权限", "正常文件"])
        self.filter_combo.setMinimumWidth(120)
        self.filter_combo.currentTextChanged.connect(self.filter_results)
        
        btn_export = QPushButton("📥 导出报告")
        btn_export.setMinimumWidth(100)
        btn_export.clicked.connect(self.export_report)
        
        table_header.addWidget(table_label)
        table_header.addStretch()
        table_header.addWidget(QLabel("筛选:"))
        table_header.addWidget(self.filter_combo)
        table_header.addWidget(btn_export)
        
        table_layout.addLayout(table_header)
        
        self.results_table = ResponsiveTable()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["文件名", "风险分", "风险等级", "检测详情"])
        self.results_table.configure_columns()  # 配置列宽策略
        self.results_table.cellClicked.connect(self.show_result_details)
        
        table_layout.addWidget(self.results_table)
        
        # 下部：详细信息
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        
        detail_label = QLabel("📝 详细信息")
        detail_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        detail_layout.addWidget(detail_label)
        
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                font-family: 'Microsoft YaHei', sans-serif;
                font-size: 13px;
            }
        """)
        self.detail_text.setPlaceholderText("点击表格中的行查看详细信息...")
        detail_layout.addWidget(self.detail_text)
        
        # 添加到分割器
        splitter.addWidget(table_widget)
        splitter.addWidget(detail_widget)
        splitter.setSizes([400, 200])
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        
        layout.addWidget(splitter)
        
        self.tab_widget.addTab(tab, "📊 扫描结果")
        
    def create_status_bar(self):
        """创建状态栏"""
        status_bar = self.statusBar()
        status_bar.showMessage("就绪 - 选择文件或文件夹开始扫描")
        
    def load_styles(self):
        """加载样式"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f6fa;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #ddd;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLineEdit {
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 8px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }
            QPushButton {
                background-color: #ecf0f1;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #d5dbdb;
            }
            QTabWidget::pane {
                border: 1px solid #ddd;
                border-radius: 4px;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #ecf0f1;
                border: 1px solid #ddd;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom-color: white;
            }
            QTableWidget {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 4px;
                gridline-color: #eee;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
            QHeaderView::section {
                background-color: #f8f9fa;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #3498db;
                font-weight: bold;
            }
        """)
        
    def connect_signals(self):
        """连接信号"""
        pass
        
    # ========== 功能方法 ==========
    
    def on_files_dropped(self, paths: list):
        """处理拖放的文件"""
        if paths:
            self.path_input.setText("; ".join(paths))
            self.log(f"[拖放] 已添加 {len(paths)} 个文件/文件夹")
            # 自动开始扫描
            self.start_scan()
    
    def select_file(self):
        """选择文件"""
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "选择要扫描的文件",
            "",
            "Mod 文件 (*.dll *.exe *.zip *.rar *.7z);;所有文件 (*.*)"
        )
        if files:
            self.path_input.setText("; ".join(files))
            
    def select_folder(self):
        """选择文件夹"""
        folder = QFileDialog.getExistingDirectory(self, "选择要扫描的文件夹")
        if folder:
            self.path_input.setText(folder)
            
    def start_scan(self):
        """开始扫描"""
        path_text = self.path_input.text().strip()
        if not path_text:
            QMessageBox.warning(self, "提示", "请先选择要扫描的文件或文件夹")
            return
            
        # 解析路径
        paths = [p.strip() for p in path_text.split(";") if p.strip()]
        
        # 验证路径
        valid_paths = []
        for p in paths:
            if os.path.exists(p):
                valid_paths.append(p)
            else:
                self.log(f"[警告] 路径不存在: {p}", "warning")
                
        if not valid_paths:
            QMessageBox.warning(self, "错误", "没有有效的扫描路径")
            return
            
        # 重置状态
        self.scan_results = []
        self.results_table.setRowCount(0)
        self.log_text.clear()
        self.risk_indicator.set_score(0, "扫描中...")
        self.stat_total.set_value("0")
        self.stat_threats.set_value("0")
        self.stat_warnings.set_value("0")
        self.stat_safe.set_value("0")
        
        # 更新UI状态
        self.btn_scan.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress_bar.setValue(0)
        
        # 启动扫描
        self.log(f"[开始] 扫描路径: {', '.join(valid_paths)}")
        self.scan_worker = ScanWorker(valid_paths, self.config)
        self.scan_worker.progress.connect(self.on_scan_progress)
        self.scan_worker.file_scanned.connect(self.on_file_scanned)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_worker.error.connect(self.on_scan_error)
        self.scan_worker.start()
        
    def cancel_scan(self):
        """取消扫描"""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.cancel()
            self.log("[取消] 扫描已取消", "warning")
            self.btn_scan.setEnabled(True)
            self.btn_cancel.setEnabled(False)
            self.progress_label.setText("已取消")
            
    def on_scan_progress(self, value: int, message: str):
        """扫描进度更新"""
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)
        
    def on_file_scanned(self, file_path: str, result: dict):
        """单个文件扫描完成"""
        self.scan_results.append(result)
        
        filename = os.path.basename(file_path)
        risk_score = result.get('risk_score', 0)
        
        # 确定风险级别
        if risk_score >= 80:
            level = "🔴 高危行为"
            level_color = "#dc3545"
        elif risk_score >= 50:
            level = "🟠 敏感权限"
            level_color = "#fd7e14"
        elif risk_score >= 30:
            level = "🟡 轻微敏感"
            level_color = "#ffc107"
        elif risk_score > 0:
            level = "🔵 低风险"
            level_color = "#17a2b8"
        else:
            level = "🟢 正常"
            level_color = "#28a745"
            
        # 获取检测详情
        details = []
        if 'yara_matches' in result:
            for match in result['yara_matches']:
                details.append(match.get('rule', 'Unknown'))
        if 'il_findings' in result:
            for finding in result['il_findings'][:3]:  # 最多显示3个
                details.append(finding.get('api', 'Unknown'))
        detail_text = ", ".join(details) if details else "未检出可疑行为"
        
        # 添加到结果表
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # 文件名
        name_item = QTableWidgetItem(filename)
        name_item.setData(Qt.ItemDataRole.UserRole, result)  # 存储完整结果
        self.results_table.setItem(row, 0, name_item)
        
        # 风险分
        score_item = QTableWidgetItem(str(risk_score))
        score_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_table.setItem(row, 1, score_item)
        
        # 威胁级别
        level_item = QTableWidgetItem(level)
        level_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.results_table.setItem(row, 2, level_item)
        
        # 详情
        detail_item = QTableWidgetItem(detail_text)
        self.results_table.setItem(row, 3, detail_item)
        
        # 设置行颜色
        for col in range(4):
            item = self.results_table.item(row, col)
            if item and risk_score >= 50:
                item.setBackground(QColor(255, 240, 240))
                
        # 更新统计
        total = len(self.scan_results)
        threats = len([r for r in self.scan_results if r.get('risk_score', 0) >= 50])
        warnings = len([r for r in self.scan_results if 30 <= r.get('risk_score', 0) < 50])
        safe = len([r for r in self.scan_results if r.get('risk_score', 0) < 30])
        
        self.stat_total.set_value(str(total))
        self.stat_threats.set_value(str(threats))
        self.stat_warnings.set_value(str(warnings))
        self.stat_safe.set_value(str(safe))
        
        # 日志
        if risk_score >= 50:
            self.log(f"[高危行为] {filename} - 风险分: {risk_score}", "danger")
        elif risk_score >= 30:
            self.log(f"[敏感权限] {filename} - 风险分: {risk_score}", "warning")
        else:
            self.log(f"[正常] {filename} - 风险分: {risk_score}", "success")
            
    def on_scan_finished(self, report: dict):
        """扫描完成"""
        self.btn_scan.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.progress_bar.setValue(100)
        self.progress_label.setText("扫描完成")
        
        # 更新风险指示器
        max_score = report.get('max_risk_score', 0)
        threat_level = report.get('overall_threat_level', '安全')
        self.risk_indicator.set_score(max_score, threat_level)
        
        self.log(f"[完成] 扫描完成，共扫描 {report.get('total_files', 0)} 个文件", "success")
        self.log(f"[统计] 发现 {report.get('threat_count', 0)} 个威胁, {report.get('warning_count', 0)} 个可疑项")
        
        # 切换到结果标签页
        self.tab_widget.setCurrentIndex(2)
        
        self.statusBar().showMessage(f"扫描完成 - 发现 {report.get('threat_count', 0)} 个威胁")
        
    def on_scan_error(self, error: str):
        """扫描错误"""
        self.btn_scan.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.log(f"[错误] {error}", "danger")
        QMessageBox.critical(self, "扫描错误", error)
        
    def log(self, message: str, level: str = "info"):
        """输出日志"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        colors = {
            "info": "#d4d4d4",
            "success": "#4ec9b0",
            "warning": "#dcdcaa",
            "danger": "#f14c4c"
        }
        color = colors.get(level, "#d4d4d4")
        
        html = f'<span style="color: #888;">[{timestamp}]</span> <span style="color: {color};">{message}</span><br>'
        self.log_text.insertHtml(html)
        
        # 滚动到底部
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
    def refresh_steam_games(self):
        """刷新 Steam 游戏列表"""
        steam_path = self.steam_finder.find_steam_installation()
        
        if steam_path:
            self.steam_path_label.setText(f"Steam 路径: {steam_path}")
            games = self.steam_finder.find_games_with_workshop()
            
            self.steam_table.setRowCount(0)
            total_mods = 0
            
            for game in games:
                # 只显示有 Workshop 内容的游戏
                if not game.workshop_path or not game.workshop_path.exists():
                    continue
                
                # 统计 Mod 数量
                try:
                    mod_count = len([d for d in game.workshop_path.iterdir() if d.is_dir()])
                except:
                    mod_count = 0
                    
                if mod_count == 0:
                    continue
                    
                total_mods += mod_count
                row = self.steam_table.rowCount()
                self.steam_table.insertRow(row)
                
                # 游戏名
                name_item = QTableWidgetItem(game.name)
                name_item.setData(Qt.ItemDataRole.UserRole, game)
                name_item.setToolTip(f"App ID: {game.app_id}")
                self.steam_table.setItem(row, 0, name_item)
                
                # Mod 数量
                count_item = QTableWidgetItem(str(mod_count))
                count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                count_item.setToolTip(f"该游戏安装了 {mod_count} 个创意工坊订阅")
                self.steam_table.setItem(row, 1, count_item)
                
                # Mod 路径
                path_item = QTableWidgetItem(str(game.workshop_path))
                path_item.setToolTip(f"完整路径: {game.workshop_path}")
                self.steam_table.setItem(row, 2, path_item)
                
                # 操作按钮组
                btn_widget = QWidget()
                btn_layout = QHBoxLayout(btn_widget)
                btn_layout.setContentsMargins(2, 2, 2, 2)  # 最小化边距
                btn_layout.setSpacing(4)  # 减小按钮间距
                
                # 扫描按钮
                btn_scan = QPushButton("扫描")
                btn_scan.setToolTip(f"扫描 {game.name} 的所有Mod文件")
                btn_scan.setStyleSheet("""
                    QPushButton {
                        background-color: #3498db;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        padding: 4px 8px;
                        font-size: 12px;
                        min-width: 45px;
                    }
                    QPushButton:hover {
                        background-color: #2980b9;
                    }
                """)
                btn_scan.clicked.connect(lambda checked, p=str(game.workshop_path): self.scan_steam_game(p))
                
                # 打开文件夹按钮
                btn_open = QPushButton("打开")
                btn_open.setToolTip("打开Mod文件夹")
                btn_open.setStyleSheet("""
                    QPushButton {
                        background-color: #95a5a6;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        padding: 4px 8px;
                        font-size: 12px;
                        min-width: 40px;
                    }
                    QPushButton:hover {
                        background-color: #7f8c8d;
                    }
                """)
                btn_open.clicked.connect(lambda checked, p=str(game.workshop_path): os.startfile(p))
                
                btn_layout.addWidget(btn_scan)
                btn_layout.addWidget(btn_open)
                btn_layout.addStretch()
                
                self.steam_table.setCellWidget(row, 3, btn_widget)
                
            self.statusBar().showMessage(f"找到 {self.steam_table.rowCount()} 个游戏，共 {total_mods} 个Mod")
        else:
            self.steam_path_label.setText("未找到 Steam 安装")
            self.statusBar().showMessage("未找到 Steam 安装")
            
    def scan_steam_game(self, game_path: str):
        """扫描单个 Steam 游戏"""
        if game_path and os.path.exists(game_path):
            self.path_input.setText(game_path)
            self.tab_widget.setCurrentIndex(0)
            self.start_scan()
            
    def scan_all_steam_games(self):
        """扫描所有 Steam 游戏的 Workshop Mod"""
        games = self.steam_finder.find_games_with_workshop()
        if games:
            # 使用 Workshop 路径而非游戏安装路径
            paths = [str(g.workshop_path) for g in games if g.workshop_path and g.workshop_path.exists()]
            if paths:
                self.path_input.setText("; ".join(paths))
                self.tab_widget.setCurrentIndex(0)
                self.start_scan()
            else:
                QMessageBox.information(self, "提示", "没有找到已安装的 Workshop Mod")
        else:
            QMessageBox.information(self, "提示", "没有找到 Steam 游戏")
            
    def show_result_details(self, row: int, column: int):
        """显示结果详情"""
        item = self.results_table.item(row, 0)
        if item:
            result = item.data(Qt.ItemDataRole.UserRole)
            if result:
                self.display_result_detail(result)
                
    def display_result_detail(self, result: dict):
        """显示详细结果"""
        html = []
        html.append(f"<h3>📄 {os.path.basename(result.get('file', 'Unknown'))}</h3>")
        html.append(f"<p><b>完整路径:</b> {result.get('file', 'Unknown')}</p>")
        html.append(f"<p><b>风险评分:</b> <span style='color: {'red' if result.get('risk_score', 0) >= 50 else 'green'};'>{result.get('risk_score', 0)}</span></p>")
        
        # YARA 匹配 - 特征检测
        yara_matches = result.get('yara_matches', [])
        if yara_matches:
            html.append("<h4>🎯 特征检测 (YARA):</h4><ul>")
            for match in yara_matches:
                html.append(f"<li><b>{match.get('rule', 'Unknown')}</b>")
                if match.get('description'):
                    html.append(f" - {match.get('description')}")
                html.append(f" (类别: {match.get('category', '未知')})</li>")
            html.append("</ul>")
            
        # IL 分析结果 - 行为分析
        il_findings = result.get('il_findings', [])
        if il_findings:
            html.append("<h4>🔬 行为分析 (IL):</h4><ul>")
            for finding in il_findings:
                html.append(f"<li><b>{finding.get('api', 'Unknown')}</b>")
                if finding.get('description'):
                    html.append(f" - {finding.get('description')}")
                html.append(f" (类型: {finding.get('category', '未知')})</li>")
            html.append("</ul>")
            
        # 如果没有发现问题
        if not yara_matches and not il_findings:
            html.append("<p style='color: green;'>✅ 未检测出可疑行为</p>")
            
        self.detail_text.setHtml("".join(html))
        
    def filter_results(self, filter_text: str):
        """筛选结果"""
        for row in range(self.results_table.rowCount()):
            item = self.results_table.item(row, 0)
            if item:
                result = item.data(Qt.ItemDataRole.UserRole)
                score = result.get('risk_score', 0) if result else 0
                
                show = True
                if filter_text == "高危行为":
                    show = score >= 50
                elif filter_text == "敏感权限":
                    show = 30 <= score < 50
                elif filter_text == "正常文件":
                    show = score < 30
                    
                self.results_table.setRowHidden(row, not show)
                
    def export_report(self):
        """导出报告"""
        if not self.scan_results:
            QMessageBox.information(self, "提示", "没有可导出的扫描结果")
            return
            
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "保存扫描报告",
            f"Mod扫描报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            "HTML 报告 (推荐) (*.html);;原始数据 (*.json)"
        )
        
        if file_path:
            try:
                report = ReportGenerator.generate_summary(self.scan_results)
                report['results'] = self.scan_results
                
                if file_path.endswith('.json'):
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(report, f, ensure_ascii=False, indent=2)
                else:
                    html = ReportGenerator.generate_html(self.scan_results)
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(html)
                        
                # 询问是否立即打开
                reply = QMessageBox.question(
                    self, 
                    "导出成功", 
                    f"报告已保存到:\n{file_path}\n\n是否立即打开查看？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.Yes:
                    os.startfile(file_path)
            except Exception as e:
                QMessageBox.critical(self, "错误", f"保存报告失败: {str(e)}")
