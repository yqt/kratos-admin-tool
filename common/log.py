import sys
import logging
import logging.handlers

log_formatter = logging.Formatter(
    '[%(asctime)s] [%(levelname)s] [%(process)s] [%(module)s:%(lineno)s %(funcName)s()] %(message)s',
    '%Y-%m-%d %H:%M:%S')

stdout_handler = logging.handlers.logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(log_formatter)
stdout_handler.setLevel(logging.INFO)

logger = logging.getLogger(__name__)
logger.addHandler(stdout_handler)
logger.setLevel(logging.INFO)
