import logging
from rich.logging import RichHandler
from rich.console import Console

console = Console()

FORMAT = "%(message)s"

OBJ_EXTRA_FMT = {
    "markup": True,
    "highlighter": False
}

logger = logging.getLogger(__name__)

def init_logger(debug):
    richHandler = RichHandler(omit_repeated_times=False, show_path=False, keywords=[], console=console)
    
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    richHandler.setFormatter(logging.Formatter(FORMAT, datefmt='[%X]'))
    logger.addHandler(richHandler)

# def init_logger(debug):
#     logger.setLevel(logging.DEBUG)

#     fileHandler = logging.FileHandler('pre2k.log')
#     fileHandler.setLevel(logging.DEBUG)
#     fileHandler.setFormatter(logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
#                                 datefmt='%Y-%m-%d %H:%M:%S'))

#     richHandler = RichHandler(omit_repeated_times=False, show_path=False, keywords=[])
#     if debug:
#         richHandler.setLevel(logging.DEBUG)
#     else:
#         richHandler.setLevel(logging.INFO)
#     richHandler.setFormatter(logging.Formatter(FORMAT, datefmt="[%X]"))

#     logger.addHandler(richHandler)
#     logger.addHandler(fileHandler)