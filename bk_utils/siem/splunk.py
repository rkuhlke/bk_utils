"""Module For Interacting with the Splunk HEC and API"""

import json
import requests
import sys
import time
import xml.etree.ElementTree as ET
from ..base import Base

class Splunk(Base):
    def __init__(self, *, username:str or None=None, password:str or None=None, baseurl:str or None=None, hecToken:str or None=None, hecEndpoint:str or None=None, name: str = 'splunk', logLevel: str = None) -> None:
        super().__init__(name=name, logLevel=logLevel)
        
        self.username = username
        self.password = password
        self.baseurl = baseurl
        self.jobID = None
        self.apiEndpoint = ':8089/services/search/jobs'
        
        self.hecToken = hecToken
        self.hecEndpoint = hecEndpoint
        
    def send2Splunk(self, event:dict) -> dict:
        """Sends JSON Events to Splunk

        Args:
            event (dict): Splunk Event in JSON Format

        Returns:
            dict: Response from Splunk
        """
        if not self.hecToken and not self.hecEndpoint:
            raise 'HEC Token and HEC Endpoint Must be Set'
        
        headers = {
            'Authorization': f'Splunk {self.hecToken}'
        }
        
        payload = {
            'event': event
        }
        
        try:
            return requests.post(
                url=self.hecEndpoint,
                data=json.dumps(payload, default=str),
                headers=headers
            )
        
        except requests.exceptions.ConnectionError as error:
            self.logger.error(f'Error Connecting to Splunk HEC: {error}')
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
    
    def querySplunk(self, query:str, *, returnEventMetaData:bool=False) -> list or None:
        """Returns a JSON response of a given Splunk Query

        Args:
            query (str): Splunk Query
            returnEventMetaData (bool, optional): If Set to True returns additional metadata related to the event. Defaults to False.

        Returns:
            list or None: List of dictionaries of given Splunk Query
        """
        if not self.username and not self.password and not self.baseurl:
            raise 'Username, Password, and BaseUrl Must Be Set'
        self.__search(query)
        self.__getStatus()
        return self.__getResults(returnEventMetaData)
    
    def __search(self, query:str) -> None:
        """Initalizes the Search

        Args:
            query (str): Splunk Query
        """
        data = {'search': f'search {query}'}
        self.logger.info(f'Searching Splunk: {query}')
        try:
            response = requests.post(
                url = self.baseurl + self.apiEndpoint,
                data=data,
                auth=(self.username, self.password),
                verify=True
            )
            
            if response.status_code != 201:
                raise f'Issue Searching Splunk: {response.text}'
        
            self.__getJobID(response)
            return
        
        except requests.exceptions.ConnectionError as error:
            self.logger.error(f'Error Connecting to Splunk HEC: {error}')
            sys.exit(1)
        except requests.exceptions.HTTPError as error:
            self.logger.error(f'HTTP Error: {error}')
            sys.exit(1)
        except requests.exceptions.URLRequired as error:
            self.logger.error(f'A valid URL is required to make a request. {error}')
            sys.exit(1)
        except requests.exceptions.Timeout as error:
            self.logger.error(f'A Timeout Error occurred. {error}')
            sys.exit(1)
        except requests.exceptions.TooManyRedirects as error:
            self.logger.error(f'Too many redirects. {error}')
            sys.exit(1)
        except requests.exceptions.RequestException as error:
            self.logger.error(f'An Unknown Error Occured: {error}')
            sys.exit(1)
        
    
    def __getStatus(self):
        """Checks the status of the current job against the Splunk Index"""
        status = 'UNKNOWN'
        self.logger.info('Checking on status of the search')
        while status != 'DONE':
            time.sleep(5)
            try:
                response = requests.post(
                    url=self.baseurl + self.apiEndpoint + '/' + self.jobID,
                    auth=(self.username, self.password),
                    verify=True
                )
                status = self.__DispatchState(response.text)
                self.logger.info(f'Search Status: {status}')
            except requests.exceptions.ConnectionError as error:
                self.logger.error(f'Error Connecting to Splunk HEC: {error}')
                sys.exit(1)
            except requests.exceptions.HTTPError as error:
                self.logger.error(f'HTTP Error: {error}')
                sys.exit(1)
            except requests.exceptions.URLRequired as error:
                self.logger.error(f'A valid URL is required to make a request. {error}')
                sys.exit(1)
            except requests.exceptions.Timeout as error:
                self.logger.error(f'A Timeout Error occurred. {error}')
                sys.exit(1)
            except requests.exceptions.TooManyRedirects as error:
                self.logger.error(f'Too many redirects. {error}')
                sys.exit(1)
            except requests.exceptions.RequestException as error:
                self.logger.error(f'An Unknown Error Occured: {error}')
                sys.exit(1)
        return
    
    def __getResults(self, returnEventMetaData:bool=False) -> list:
        """Returns the results of the Search against the Splunk Index

        Args:
            returnEventMetaData (bool): if set to True returns additonal meta data about the search. Defaults to False

        Returns:
            list: Results from the Splunk Index
        """
        data = {'output_mode': 'json'}
        offset = 0
        returned_all_results = False
        results = list()
        self.logger.info('Generating Results from Splunk')
        while not returned_all_results:
            try:
                resp = requests.get(
                    url=self.baseurl + self.apiEndpoint + '/' + self.jobID + f'/results?count=50000&offset={str(offset)}',
                    data=data,
                    auth=(self.username, self.password),
                    verify=True
                )
            except requests.exceptions.ConnectionError as error:
                self.logger.error(f'Error Connecting to Splunk HEC: {error}')
                sys.exit(1)
            except requests.exceptions.HTTPError as error:
                self.logger.error(f'HTTP Error: {error}')
                sys.exit(1)
            except requests.exceptions.URLRequired as error:
                self.logger.error(f'A valid URL is required to make a request. {error}')
                sys.exit(1)
            except requests.exceptions.Timeout as error:
                self.logger.error(f'A Timeout Error occurred. {error}')
                sys.exit(1)
            except requests.exceptions.TooManyRedirects as error:
                self.logger.error(f'Too many redirects. {error}')
                sys.exit(1)
            except requests.exceptions.RequestException as error:
                self.logger.error(f'An Unknown Error Occured: {error}')
                sys.exit(1)
            
            response_data = json.loads(resp.text)
            if len(response_data.get('results')) == 0:
                returned_all_results = True
            else:
                if returnEventMetaData:
                    results += response_data.get('results')
                for item in response_data.get('results'):
                    results.append(json.loads(item.get("_raw")))
                offset += 50000
        self.logger.info('Done!')
        return results
            
    
    def __getJobID(self, responseContent):
        root = ET.fromstring(responseContent.text)
        for tag in root:
            job_id = tag.text
        self.jobID = job_id
        return 
    
    def __DispatchState(self, xml_text):
        root = ET.fromstring(xml_text)
        dispatchState = ''
        for tag in root:
            if 'content' in tag.tag:
                for tag2 in tag:
                    for tag3 in tag2:
                        if tag3.attrib['name'] == 'dispatchState':
                            dispatchState = tag3.text
        return dispatchState