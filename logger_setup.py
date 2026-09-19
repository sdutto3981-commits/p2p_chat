"""
Configurazione logging cross-platform. I log finiscono in ~/P2PChat/logs/.
"""

import logging
import platform
import os
from datetime import datetime

from app_paths import LOGS_DIR, ensure_app_structure


def setup_logging(hostname):
    ensure_app_structure()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filepath = os.path.join(LOGS_DIR, f"peer_{hostname}_{timestamp}.log")

    logger = logging.getLogger(f"p2p_node.{hostname}")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d | %(levelname)-7s | %(threadName)-16s | %(funcName)-18s | %(message)s",
        datefmt="%H:%M:%S"
    )
    file_handler = logging.FileHandler(log_filepath, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.info(f"OS: {platform.system()} {platform.release()} | Python {platform.python_version()}")
    return logger, log_filepath
