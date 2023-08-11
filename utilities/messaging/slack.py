import json
import requests

from ..base import Base

class Slack(Base):
    def __init__(self, *, name: str = 'slack', logLevel: str = None) -> None:
        super().__init__(name=name, logLevel=logLevel)
    
    def send2Slack(self, slackWebhookUrl:str, message:str):
        headers = {
            'Content-Type': 'application/json'
        }
        
        payload = {
            'text': message
        }
        
        try:
            return 200, requests.post(url=slackWebhookUrl, headers=headers, data=json.dumps(payload))
        except Exception as error:
            self.logger.error(f'Send Message To Slack Error')
            self.logger.error(error)
            raise error
            