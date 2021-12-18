import logging
import requests


class TelegramBots:
    def __init__(self, logLevel=""):
        self.logger = logging.getLogger(__name__)
        ch = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        if logLevel.lower() == "debug":
            self.logger.setLevel(logging.DEBUG)
        elif logLevel.lower() == "error":
            self.logger.setLevel(logging.ERROR)
        else:
            self.logger.setLevel(logging.INFO)
    
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
