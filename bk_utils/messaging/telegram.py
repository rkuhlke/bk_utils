import logging
import requests
from ..base import Base


class Telegram(Base):
    def __init__(self, *, name: str = 'telegram', logLevel: str = None) -> None:
        super().__init__(name=name, logLevel=logLevel)
    
    def send2Telegram(self, bot_id:str, group:str, text:str):
        """
        sends the message to telegram
        :param group: choose what telegram group to send message to
        :param text: allows you to choose what message to send
        :return: message
        """
        # sends a message to telegram
        try:
            self.logger.info("Successfully Sent Message to Telegram")
            return requests.get(f"https://api.telegram.org/bot{bot_id}/sendMessage?chat_id={group}=&text={text}")
        except requests.RequestException as error:
            self.logger.error(f"Error: {error}")
            raise error
        
        
