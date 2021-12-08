import requests

class Telegram:
    def send2Telegram(bot_id, group, text):
        """
        sends the message to telegram
        :param group: choose what telegram group to send message to
        :param text: allows you to choose what message to send
        :return: message
        """
        # sends a message to telegram
        return requests.get(f"https://api.telegram.org/bot{bot_id}/sendMessage?chat_id={group}=&text={text}")
