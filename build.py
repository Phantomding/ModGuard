"""
ModGuard 打包脚本
使用 PyInstaller 打包成 Windows 可执行文件
"""
import os
import sys
import shutil
import subprocess
from pathlib import Path

# 项目根目录
ROOT_DIR = Path(__file__).parent
DIST_DIR = ROOT_DIR / "dist"
BUILD_DIR = ROOT_DIR / "build"

# 应用信息
APP_NAME = "ModGuard"
APP_VERSION = "2.1.0"
APP_ICON = ROOT_DIR / "assets" / "icon.ico"


def clean():
    """清理之前的构建"""
    print("🧹 清理旧的构建文件...")
    for folder in [DIST_DIR, BUILD_DIR]:
        if folder.exists():
            shutil.rmtree(folder)
    
    # 清理 spec 文件
    for spec in ROOT_DIR.glob("*.spec"):
        spec.unlink()
    print("   ✅ 清理完成")


def check_dependencies():
    """检查打包依赖"""
    print("📦 检查打包依赖...")
    try:
        import PyInstaller
        print(f"   ✅ PyInstaller {PyInstaller.__version__}")
    except ImportError:
        print("   ❌ PyInstaller 未安装")
        print("   正在安装 PyInstaller...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
        print("   ✅ PyInstaller 安装完成")


def create_spec_file():
    """创建 PyInstaller spec 文件"""
    spec_content = f'''# -*- mode: python ; coding: utf-8 -*-
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
    hooksconfig={{}},
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
    name='{APP_NAME}',
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
    name='{APP_NAME}',
)
'''
    
    spec_path = ROOT_DIR / f"{APP_NAME}.spec"
    with open(spec_path, 'w', encoding='utf-8') as f:
        f.write(spec_content)
    print(f"   ✅ 创建 {APP_NAME}.spec")
    return spec_path


def create_version_info():
    """创建 Windows 版本信息文件"""
    version_parts = APP_VERSION.split('.')
    while len(version_parts) < 4:
        version_parts.append('0')
    
    version_info = f'''# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({version_parts[0]}, {version_parts[1]}, {version_parts[2]}, {version_parts[3]}),
    prodvers=({version_parts[0]}, {version_parts[1]}, {version_parts[2]}, {version_parts[3]}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'080404b0',
        [StringStruct(u'CompanyName', u'ModGuard'),
        StringStruct(u'FileDescription', u'Steam Mod 安全检测工具'),
        StringStruct(u'FileVersion', u'{APP_VERSION}'),
        StringStruct(u'InternalName', u'{APP_NAME}'),
        StringStruct(u'LegalCopyright', u'MIT License'),
        StringStruct(u'OriginalFilename', u'{APP_NAME}.exe'),
        StringStruct(u'ProductName', u'{APP_NAME}'),
        StringStruct(u'ProductVersion', u'{APP_VERSION}')])
      ]), 
    VarFileInfo([VarStruct(u'Translation', [2052, 1200])])
  ]
)
'''
    
    version_path = ROOT_DIR / "file_version_info.txt"
    with open(version_path, 'w', encoding='utf-8') as f:
        f.write(version_info)
    print("   ✅ 创建版本信息文件")


def create_icon_placeholder():
    """检查图标文件"""
    icon_dir = ROOT_DIR / "assets"
    icon_path = icon_dir / "icon.ico"
    
    if not icon_dir.exists():
        icon_dir.mkdir(parents=True)
    
    if not icon_path.exists():
        print("   ⚠️ 未找到 icon.ico，将使用默认图标")
        print(f"   💡 提示：可以将图标文件放到 {icon_path}")
    else:
        print("   ✅ 找到应用图标")


def build():
    """执行打包"""
    print(f"\n🔨 开始打包 {APP_NAME} v{APP_VERSION}...")
    
    spec_path = create_spec_file()
    
    # 运行 PyInstaller
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "--noconfirm",
        str(spec_path)
    ]
    
    print("   正在打包，请稍候...")
    result = subprocess.run(cmd, cwd=str(ROOT_DIR))
    
    if result.returncode == 0:
        print("\n✅ 打包成功！")
        output_dir = DIST_DIR / APP_NAME
        print(f"   📁 输出目录: {output_dir}")
        
        # 显示文件大小
        if output_dir.exists():
            total_size = sum(f.stat().st_size for f in output_dir.rglob('*') if f.is_file())
            print(f"   📊 总大小: {total_size / 1024 / 1024:.1f} MB")
    else:
        print("\n❌ 打包失败，请检查错误信息")
        return False
    
    return True


def create_portable_zip():
    """创建便携版 ZIP"""
    print("\n📦 创建便携版 ZIP...")
    
    output_dir = DIST_DIR / APP_NAME
    if not output_dir.exists():
        print("   ❌ 找不到打包输出目录")
        return
    
    zip_name = f"{APP_NAME}_v{APP_VERSION}_Portable"
    zip_path = DIST_DIR / zip_name
    
    shutil.make_archive(str(zip_path), 'zip', str(DIST_DIR), APP_NAME)
    
    final_zip = DIST_DIR / f"{zip_name}.zip"
    print(f"   ✅ 创建完成: {final_zip}")
    print(f"   📊 文件大小: {final_zip.stat().st_size / 1024 / 1024:.1f} MB")


def main():
    """主函数"""
    print("=" * 50)
    print(f"  🛡️ {APP_NAME} 打包工具 v{APP_VERSION}")
    print("=" * 50)
    
    # 检查依赖
    check_dependencies()
    
    # 检查图标
    create_icon_placeholder()
    
    # 创建版本信息
    create_version_info()
    
    # 询问是否清理
    if (DIST_DIR / APP_NAME).exists():
        print("\n⚠️ 发现之前的构建，是否清理？")
        choice = input("   输入 y 清理，其他跳过: ").strip().lower()
        if choice == 'y':
            clean()
    
    # 执行打包
    if build():
        # 创建便携版
        print("\n是否创建便携版 ZIP？")
        choice = input("   输入 y 创建，其他跳过: ").strip().lower()
        if choice == 'y':
            create_portable_zip()
    
    print("\n" + "=" * 50)
    print("  打包流程结束")
    print("=" * 50)


if __name__ == "__main__":
    main()
