"""
Steam 路径发现模块
自动检测 Steam 安装位置和游戏库
"""
import os
import re
import winreg
from pathlib import Path
from typing import List, Optional, Dict
from dataclasses import dataclass

from config import STEAM_CONFIG


@dataclass
class SteamGame:
    """Steam 游戏信息"""
    app_id: str
    name: str
    install_path: Path
    workshop_path: Optional[Path] = None
    
    def has_workshop(self) -> bool:
        return self.workshop_path is not None and self.workshop_path.exists()


@dataclass
class SteamLibrary:
    """Steam 游戏库"""
    path: Path
    games: List[SteamGame]


class SteamFinder:
    """Steam 路径发现器"""
    
    def __init__(self):
        self.steam_path: Optional[Path] = None
        self.libraries: List[SteamLibrary] = []
        
    def find_steam_installation(self) -> Optional[Path]:
        """查找 Steam 安装路径"""
        # 方法1: 从注册表读取
        steam_path = self._find_from_registry()
        if steam_path:
            self.steam_path = steam_path
            return steam_path
            
        # 方法2: 检查默认路径
        for path_str in STEAM_CONFIG.default_paths:
            path = Path(path_str)
            if path.exists() and (path / "steam.exe").exists():
                self.steam_path = path
                return path
                
        return None
    
    def _find_from_registry(self) -> Optional[Path]:
        """从 Windows 注册表读取 Steam 路径"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, 
                STEAM_CONFIG.registry_key
            )
            value, _ = winreg.QueryValueEx(key, "InstallPath")
            winreg.CloseKey(key)
            
            path = Path(value)
            if path.exists():
                return path
        except (WindowsError, FileNotFoundError):
            pass
        return None
    
    def find_all_libraries(self) -> List[SteamLibrary]:
        """查找所有 Steam 游戏库"""
        if not self.steam_path:
            self.find_steam_installation()
            
        if not self.steam_path:
            return []
            
        libraries = []
        
        # 主库
        main_steamapps = self.steam_path / "steamapps"
        if main_steamapps.exists():
            lib = SteamLibrary(path=main_steamapps, games=[])
            libraries.append(lib)
        
        # 解析 libraryfolders.vdf 查找其他库
        vdf_path = main_steamapps / "libraryfolders.vdf"
        if vdf_path.exists():
            extra_paths = self._parse_library_folders(vdf_path)
            for path in extra_paths:
                steamapps = path / "steamapps"
                if steamapps.exists() and steamapps not in [l.path for l in libraries]:
                    lib = SteamLibrary(path=steamapps, games=[])
                    libraries.append(lib)
        
        self.libraries = libraries
        return libraries
    
    def _parse_library_folders(self, vdf_path: Path) -> List[Path]:
        """解析 libraryfolders.vdf 文件"""
        paths = []
        try:
            content = vdf_path.read_text(encoding='utf-8', errors='ignore')
            # 简单正则匹配路径
            # "path"		"D:\\SteamLibrary"
            pattern = r'"path"\s+"([^"]+)"'
            matches = re.findall(pattern, content)
            for match in matches:
                # 处理转义的反斜杠
                path_str = match.replace('\\\\', '\\')
                paths.append(Path(path_str))
        except Exception:
            pass
        return paths
    
    def find_games_with_workshop(self) -> List[SteamGame]:
        """查找所有有创意工坊内容的游戏"""
        if not self.libraries:
            self.find_all_libraries()
            
        games = []
        
        for library in self.libraries:
            workshop_path = library.path / "workshop" / "content"
            if not workshop_path.exists():
                continue
                
            # 遍历创意工坊目录下的游戏ID
            for app_folder in workshop_path.iterdir():
                if app_folder.is_dir() and app_folder.name.isdigit():
                    app_id = app_folder.name
                    game_name = self._get_game_name(library.path, app_id)
                    
                    game = SteamGame(
                        app_id=app_id,
                        name=game_name,
                        install_path=self._get_game_install_path(library.path, app_id),
                        workshop_path=app_folder
                    )
                    games.append(game)
                    
        return games
    
    def _get_game_name(self, steamapps_path: Path, app_id: str) -> str:
        """从 appmanifest 获取游戏名称"""
        manifest_path = steamapps_path / f"appmanifest_{app_id}.acf"
        if manifest_path.exists():
            try:
                content = manifest_path.read_text(encoding='utf-8', errors='ignore')
                match = re.search(r'"name"\s+"([^"]+)"', content)
                if match:
                    return match.group(1)
            except Exception:
                pass
        return f"Unknown Game ({app_id})"
    
    def _get_game_install_path(self, steamapps_path: Path, app_id: str) -> Path:
        """获取游戏安装路径"""
        manifest_path = steamapps_path / f"appmanifest_{app_id}.acf"
        if manifest_path.exists():
            try:
                content = manifest_path.read_text(encoding='utf-8', errors='ignore')
                match = re.search(r'"installdir"\s+"([^"]+)"', content)
                if match:
                    return steamapps_path / "common" / match.group(1)
            except Exception:
                pass
        return steamapps_path / "common"
    
    def get_workshop_mods(self, game: SteamGame) -> List[Dict]:
        """获取指定游戏的所有创意工坊 Mod"""
        mods = []
        
        if not game.workshop_path or not game.workshop_path.exists():
            return mods
            
        for mod_folder in game.workshop_path.iterdir():
            if mod_folder.is_dir():
                mod_info = {
                    'id': mod_folder.name,
                    'path': mod_folder,
                    'name': self._get_mod_name(mod_folder),
                    'size': self._get_folder_size(mod_folder),
                }
                mods.append(mod_info)
                
        return mods
    
    def _get_mod_name(self, mod_path: Path) -> str:
        """尝试获取 Mod 名称"""
        # 尝试常见的信息文件
        for info_file in ['mod.json', 'info.json', 'modinfo.lua', 'about.xml']:
            info_path = mod_path / info_file
            if info_path.exists():
                try:
                    content = info_path.read_text(encoding='utf-8', errors='ignore')
                    # 简单提取名称
                    match = re.search(r'["\']?name["\']?\s*[:=]\s*["\']([^"\']+)["\']', content, re.I)
                    if match:
                        return match.group(1)
                except Exception:
                    pass
        return f"Mod {mod_path.name}"
    
    def _get_folder_size(self, folder: Path) -> int:
        """计算文件夹大小"""
        total = 0
        try:
            for item in folder.rglob('*'):
                if item.is_file():
                    total += item.stat().st_size
        except Exception:
            pass
        return total


# === 便捷函数 ===
def auto_discover_steam() -> Optional[SteamFinder]:
    """自动发现 Steam 并返回 Finder 实例"""
    finder = SteamFinder()
    if finder.find_steam_installation():
        finder.find_all_libraries()
        return finder
    return None
