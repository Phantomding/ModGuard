"""
日志工具
"""
import os
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

# 全局日志实例
_loggers = {}


def setup_logger(
    name: str = 'modguard',
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    console: bool = True
) -> logging.Logger:
    """
    设置日志记录器
    
    Args:
        name: 日志名称
        level: 日志级别
        log_file: 日志文件路径
        console: 是否输出到控制台
        
    Returns:
        Logger 实例
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 清除已有处理器
    logger.handlers.clear()
    
    # 格式器
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # 控制台处理器
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # 文件处理器
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(
            log_file, 
            encoding='utf-8',
            mode='a'
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    _loggers[name] = logger
    return logger


def get_logger(name: str = 'modguard') -> logging.Logger:
    """获取日志记录器"""
    if name in _loggers:
        return _loggers[name]
    return setup_logger(name)


def log_scan_start(target: str):
    """记录扫描开始"""
    logger = get_logger()
    logger.info("=" * 50)
    logger.info(f"开始扫描: {target}")
    logger.info(f"时间: {datetime.now().isoformat()}")
    logger.info("=" * 50)


def log_scan_result(threat_count: int, duration: float):
    """记录扫描结果"""
    logger = get_logger()
    logger.info("-" * 50)
    logger.info(f"扫描完成")
    logger.info(f"发现威胁: {threat_count}")
    logger.info(f"耗时: {duration:.2f} 秒")
    logger.info("-" * 50)


def log_threat(severity: str, rule: str, file: str):
    """记录威胁"""
    logger = get_logger()
    
    level = {
        'critical': logging.CRITICAL,
        'high': logging.ERROR,
        'medium': logging.WARNING,
        'low': logging.INFO,
        'info': logging.DEBUG,
    }.get(severity.lower(), logging.INFO)
    
    logger.log(level, f"[{severity.upper()}] {rule} -> {file}")


class ScanLogger:
    """扫描日志记录器"""
    
    def __init__(self, log_dir: str = None):
        if log_dir is None:
            log_dir = Path(__file__).parent.parent / 'logs'
            
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # 创建本次扫描的日志文件
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.log_file = self.log_dir / f'scan_{timestamp}.log'
        
        self.logger = setup_logger(
            name=f'scan_{timestamp}',
            log_file=str(self.log_file)
        )
        
    def start(self, target: str):
        """记录开始"""
        self.logger.info(f"=== 扫描开始: {target} ===")
        
    def progress(self, current: int, total: int, file: str):
        """记录进度"""
        self.logger.debug(f"[{current}/{total}] {file}")
        
    def threat(self, severity: str, rule: str, file: str, desc: str):
        """记录威胁"""
        self.logger.warning(f"[威胁] {severity} | {rule} | {file}")
        self.logger.warning(f"  └── {desc}")
        
    def finish(self, threat_count: int, duration: float):
        """记录完成"""
        self.logger.info(f"=== 扫描完成 ===")
        self.logger.info(f"威胁数: {threat_count}")
        self.logger.info(f"耗时: {duration:.2f}s")
        
    def get_log_path(self) -> Path:
        """获取日志文件路径"""
        return self.log_file
