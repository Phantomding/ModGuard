# ModGuard
ModGuard v2.1：基于 Python/PyQt6 构建的现代化 Steam Mod 静态分析工具。  核心特性包括：  双重检测引擎：结合 YARA 规则库与 dnfile IL 指令分析，精准识别恶意特征。  深度扫描：支持递归解压 ZIP/RAR/7Z 档案，通过白名单机制过滤合法框架（如 BepInEx）。  可视化审计：提供风险评分、敏感权限列表及 HTML 审计报告。  反混淆检测：专门针对 Base64 载荷、动态加载及常见 .NET 混淆器进行识别。
