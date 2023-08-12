"""Module that provides funtions to interact with the Jira API"""

import json
import requests
from requests.auth import HTTPBasicAuth
from ..base import Base

class Jira(Base):
    def __init__(self, *, username:str, apiToken:str, baseUrl:str, projectKey:str, name: str = 'jira', logLevel: str = None) -> None:
        super().__init__(name=name, logLevel=logLevel)
        
        self.baseUrl = baseUrl,
        self.projectKey = projectKey
        self.auth = HTTPBasicAuth(username=username, password=apiToken)
        
        self.getHeaders = {
            'Accept': 'application/json'
        }
        
        self.postHeaders = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
    def createIssue(self, payload:dict) -> dict:
        """Creates a Jira Issue

        Args:
            payload (dict): Issue Payload

        Returns:
            dict: Issue Response
        """
        url = f'{self.baseUrl}/rest/api/3/issue/'
        
        try:
            return requests.post(
                url=url,
                data=json.dumps(payload),
                headers=self.postHeaders,
                auth=self.auth
            ).text
            
        except requests.exceptions.ConnectionError as error:
            self.logger.error(f'Error Connecting to Jira API: {error}')
            return None
        except requests.exceptions.HTTPError as error:
            self.logger.error(f'HTTP Error: {error}')
            return None
        except requests.exceptions.URLRequired as error:
            self.logger.error(f'A valid URL is required to make a request. {error}')
            return None
        except requests.exceptions.Timeout as error:
            self.logger.error(f'A Timeout Error occurred. {error}')
            return None
        except requests.exceptions.TooManyRedirects as error:
            self.logger.error(f'Too many redirects. {error}')
            return None
        except requests.exceptions.RequestException as error:
            self.logger.error(f'An Unknown Error Occured: {error}')
            return None
        
    def getCurrentSprintID(self) -> str:
        """Returns the Active Sprint ID For Given Project Key

        Returns:
            str: Current Sprint ID as string
        """
        url = f'{self.baseUrl}/rest/greenhopper/1.0/sprint/picker?query=&projectKey={self.projectKey}'
        
        try:
            response = requests.get(
                url=url,
                headers=self.getHeaders,
                auth=self.auth
            )
        
        except requests.exceptions.ConnectionError as error:
            self.logger.error(f'Error Connecting to Jira API: {error}')
            return None
        except requests.exceptions.HTTPError as error:
            self.logger.error(f'HTTP Error: {error}')
            return None
        except requests.exceptions.URLRequired as error:
            self.logger.error(f'A valid URL is required to make a request. {error}')
            return None
        except requests.exceptions.Timeout as error:
            self.logger.error(f'A Timeout Error occurred. {error}')
            return None
        except requests.exceptions.TooManyRedirects as error:
            self.logger.error(f'Too many redirects. {error}')
            return None
        except requests.exceptions.RequestException as error:
            self.logger.error(f'An Unknown Error Occured: {error}')
            return None
        
        for sprint in response.json().get('allMatches'):
            if sprint.get('stateKey') == 'ACTIVE':
                return sprint.get('id')