import logging

logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('boto3').setLevel(logging.WARNING)

class Base:
    def __init__(self, *, name:str='base', logLevel:str or None=None) -> None:
        self.logger = logging.getLogger(f'utilities-{name}')
        if not self.logger.handlers:
            ch = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
        
        if not logLevel:
            self.logger.setLevel(logging.INFO)
        elif logLevel.lower() == 'debug':
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.ERROR)