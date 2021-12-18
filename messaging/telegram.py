import requests
from logger import setLogLevel

class TelegramBots:
    def __init__(self, logLevel=""):
        self.logger = setLogLevel(logLevel, __name__)
    
    def send2Telegram(self, bot_id, group, text):
        """
        sends the message to telegram
        :param group: choose what telegram group to send message to
        :param text: allows you to choose what message to send
        :return: message
        """
        # sends a message to telegram
        try:
            requests.get(f"https://api.telegram.org/bot{bot_id}/sendMessage?chat_id={group}=&text={text}")
        except requests.RequestException as error:
            self.logger.error(f"Error: {error}")
        self.logger.info("Successfully Sent Message to Telegram")
        return
