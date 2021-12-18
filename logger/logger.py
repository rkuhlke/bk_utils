import logging

def setLogLevel(logLevel:str, name):
    logger = logging.getLogger(name)
    ch = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if logLevel.lower() == "debug":
        logger.setLevel(logging.DEBUG)
    elif logLevel.lower() == "error":
        logger.setLevel(logging.ERROR)
    else:
        logger.setLevel(logging.INFO)
    