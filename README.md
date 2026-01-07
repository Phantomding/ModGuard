# 🛡️ ModGuard v2.1

**Steam Mod 安全检测工具** - 专为普通玩家设计，帮助识别创意工坊中的可疑 Mod

> ⚠️ **免责声明**：本工具仅提供风险提示，检测结果仅供参考。通过检测不代表绝对安全，未通过检测也不代表一定恶意。请结合实际情况谨慎判断。

## ✨ 功能特性

### 🔍 多层检测引擎
- **YARA 特征扫描**: 基于规则匹配检测已知威胁特征
- **IL 行为分析**: 深度解析 .NET DLL 中的敏感 API 调用
- **混淆检测**: 识别代码混淆、加密载荷等可疑技术
- **压缩包扫描**: 自动解压并扫描 ZIP/7Z/RAR 内部文件

### 🎮 Steam 集成
- 自动发现 Steam 安装路径
- 扫描 Workshop 创意工坊订阅内容
- 显示每个游戏的 Mod 数量
- 一键扫描 / 打开 Mod 文件夹

### 📂 便捷操作
- **拖放扫描**: 直接拖放文件或文件夹到窗口即可扫描
- **批量扫描**: 支持同时扫描多个文件/文件夹
- **实时日志**: 扫描过程实时显示检测进度

### 📊 友好的结果展示
- 风险评分 (0-100)
- 风险等级分类（高风险/敏感权限/轻微敏感/低风险）
- 详细的检测报告
- 导出 HTML 报告（推荐）或 JSON 原始数据

## 🚀 快速开始

### 安装依赖

```bash
# 基础依赖
pip install -r requirements.txt

# 可选：支持更多压缩格式
pip install py7zr rarfile
```

### 运行程序

```bash
python main.py
```

## 📁 项目结构

```
ModGuard/
├── main.py                 # 程序入口
├── config.py               # 全局配置
├── requirements.txt        # 依赖列表
│
├── core/                   # 核心引擎
│   ├── scanner.py          # 扫描调度器（支持压缩包）
│   ├── yara_engine.py      # YARA 规则引擎
│   ├── il_analyzer.py      # .NET IL 分析器（带白名单）
│   ├── steam_finder.py     # Steam 路径发现
│   └── report.py           # 报告生成器（HTML/JSON）
│
├── rules/                  # 检测规则
│   ├── malicious.yar       # 恶意行为规则
│   ├── suspicious.yar      # 可疑行为规则
│   └── ...
│
├── gui/                    # 用户界面
│   ├── main_window.py      # 主窗口（响应式布局）
│   └── styles.qss          # 样式表
│
└── assets/                 # 资源文件
```

## 🎯 检测能力

### 🔴 高风险行为
- Steam 凭证窃取 (ssfn, loginusers.vdf, config.vdf)
- 数据外传 (Discord Webhook, Telegram Bot, 自建服务器)
- 远程代码执行 / 动态加载
- 代码混淆 (ConfuserEx, Dotfuscator 等)
- 加密有效载荷 (Base64 + Assembly.Load)

### 🟠 敏感权限
- 网络通信 (HttpClient, WebRequest, Socket)
- 进程操作 (Process.Start, CreateProcess)
- 注册表访问 (Registry, RegOpenKey)
- 文件系统操作 (File.ReadAllBytes, Directory)
- 屏幕截图 / 剪贴板访问

### 🟡 轻微敏感
- 加密解密调用 (AES, SHA, MD5)
- 反射操作 (Assembly, MethodInfo)
- 环境信息获取 (Environment, SystemInfo)

### ✅ 智能白名单
自动识别并降低以下合法框架的风险评分：
- BepInEx / MelonLoader / Harmony
- Unity / UnityEngine
- Steamworks.NET
- MonoMod / 0Harmony

## 🔐 混淆检测

针对恶意作者常用的代码保护手段：

| 混淆技术 | 检测方式 |
|---------|---------|
| .NET 混淆器 | 识别 ConfuserEx, Dotfuscator 等特征 |
| Base64 编码 | 检测 FromBase64String + Assembly.Load 组合 |
| 字符串混淆 | 识别字符数组拼接、XOR 解密模式 |
| 加密载荷 | 检测 AES/DES + 动态加载组合 |
| 压缩壳 | 检测 DeflateStream/GZip + 反射加载 |
| 非法命名 | 检测使用不可打印字符作为标识符 |

## ⚠️ 注意事项

1. **检测结果仅供参考**: 工具提供的是风险提示，不是最终定论
2. **误报可能存在**: 某些合法 Mod 框架也可能触发检测，已尽量通过白名单机制减少
3. **漏报风险**: 新型或高度定制的恶意代码可能绑过检测
4. **建议做法**: 
   - 优先使用订阅量大、评价好的 Mod
   - 查看 Mod 评论区是否有安全问题反馈
   - 对高风险检测结果保持警惕

## 🛠️ 技术栈

- **Python 3.8+**
- **PyQt6** - 现代化 GUI 框架
- **yara-python** - 恶意软件特征匹配（可选）
- **dnfile** - .NET PE 文件解析
- **py7zr / rarfile** - 压缩格式支持（可选）

## 📝 更新日志

### v2.1 (2026-01-07)
- ✨ 新增拖放扫描功能
- ✨ 新增压缩包内部文件扫描 (ZIP/7Z/RAR)
- ✨ 新增混淆代码检测规则
- 🔧 优化 Steam Workshop 路径识别
- 🔧 优化表格列宽自适应
- 🔧 术语优化：使用"风险/敏感权限/行为"替代"敏感度"

### v2.0
- 🎉 全新 GUI 界面
- 🎉 多引擎扫描架构
- 🎉 Steam 游戏集成
- 🎉 HTML 报告导出

## 📄 许可证

MIT License

---

**如果这个工具对你有帮助，欢迎 Star ⭐**
