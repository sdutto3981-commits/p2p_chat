"""
Configurazione logging cross-platform (Windows/Mac/Linux).
I log finiscono sia su file dettagliato che, tramite callback opzionale,
possono essere specchiati su una UI.
"""

import logging
import os
import platform
from datetime import datetime


def setup_logging(hostname):
    """
    Crea un logger che scrive su file in ~/p2p_chat_logs/.
    os.path.expanduser e os.path.join gestiscono automaticamente
    le differenze di path tra Windows (\\) e Mac/Linux (/).
    """
    log_dir = os.path.join(os.path.expanduser("~"), "p2p_chat_logs")
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filepath = os.path.join(log_dir, f"peer_{hostname}_{timestamp}.log")

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
