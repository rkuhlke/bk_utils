import logging

def setLogLevel(logLevel:str, name):
    logger = logging.getLogger(name)
    ch = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if logLevel.lower() == "debug":
        return logger.setLevel(logging.DEBUG)
    elif logLevel.lower() == "error":
        return logger.setLevel(logging.ERROR)
    else:
        return logger.setLevel(logging.INFO)
    