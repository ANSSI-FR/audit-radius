# -*- coding: utf-8 -*-
"""
Basic logging module.
"""

import logging
import logging.handlers


ERROR_LOG_FILE_PATH = "error.log"

def __build_logger(
        logger_name,
        logging_level,
        logging_format,
        logging_handler=logging.StreamHandler()
    ):

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging_level)

    # Create a console handler
    handler_ = logging_handler
    handler_.setLevel(logging_level)

    # Define the logging format
    formatter_ = logging.Formatter(
        logging_format
    )
    handler_.setFormatter(formatter_)

    # Add the handler
    logger.addHandler(handler_)

    return logger


# Default logger
g_default_logger = __build_logger( # pylint: disable=C0103
    "default_logger",
    logging.INFO,
    "%(levelname)s: %(message)s"
)

# Exception / error logger
g_exception_logger = __build_logger( # pylint: disable=C0103
    "exception_logger",
    logging.ERROR,
    "%(levelname)s: %(message)s",
    logging_handler=logging.handlers.RotatingFileHandler(
        ERROR_LOG_FILE_PATH,
        maxBytes=20000,
        backupCount=3
    )
)

# Traffic logger. Used to display the frames that are sent and received
g_traffic_logger = __build_logger( # pylint: disable=C0103
    "traffic_logger",
    logging.INFO,
    "%(levelname)s: %(message)s"
)
