"""
ModGuard 2.0 - Steam Mod 恶意代码检测工具
面向小白用户的安全检测工具
"""
import sys
import os

# 确保可以导入项目模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from gui.main_window import MainWindow
from config import APP_NAME, APP_VERSION


def main():
    # 启用高DPI支持
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    
    # 创建 Qt 应用实例
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    
    # 设置默认字体
    font = QFont("Microsoft YaHei", 10)
    app.setFont(font)
    
    # 创建并显示主窗口
    window = MainWindow()
    window.show()
    
    print(f"🛡️ {APP_NAME} v{APP_VERSION} 已启动")
    print("=" * 40)
    
    # 进入事件循环
    sys.exit(app.exec())


if __name__ == "__main__":
    main()