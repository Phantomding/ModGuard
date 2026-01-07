# -*- mode: python ; coding: utf-8 -*-
# ModGuard PyInstaller Spec File

import sys
from pathlib import Path

block_cipher = None

# 项目路径
ROOT = Path(SPECPATH)

# 数据文件
datas = [
    # 规则文件
    (str(ROOT / 'rules'), 'rules'),
    # 资源文件
    (str(ROOT / 'assets'), 'assets'),
    # 样式文件
    (str(ROOT / 'gui' / 'styles.qss'), 'gui'),
]

# 隐式导入（可能被漏掉的模块）
hiddenimports = [
    'PyQt6.QtWidgets',
    'PyQt6.QtCore', 
    'PyQt6.QtGui',
    'dnfile',
    'pefile',
]

# 尝试添加可选依赖
try:
    import yara
    hiddenimports.append('yara')
except ImportError:
    pass

try:
    import py7zr
    hiddenimports.append('py7zr')
except ImportError:
    pass

try:
    import rarfile
    hiddenimports.append('rarfile')
except ImportError:
    pass

a = Analysis(
    ['main.py'],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'tkinter',
        'unittest',
        'test',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ModGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # 不显示控制台窗口
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / 'assets' / 'icon.ico') if (ROOT / 'assets' / 'icon.ico').exists() else None,
    version='file_version_info.txt' if Path('file_version_info.txt').exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ModGuard',
)
