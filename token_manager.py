from collections import defaultdict
import ujson as json
import time
import os
import requests
from requests_oauthlib import OAuth1
from random import shuffle
import threading
import logging

logging.getLogger("urllib3").propagate = False
logging.getLogger("requests").propagate = False
logging.getLogger("requests_oauthlib.oauth1_auth").propagate = False
logging.getLogger("oauthlib").propagate = False
logging.basicConfig(level=logging.DEBUG,format='%(asctime)s %(levelname)s %(message)s')


class TokenManager:
    '''This class handles loading in Twitter oauth user keys and manages rate-limits for
    those keys.'''

    def __init__(self):
        self.consumer_key = os.environ['TWITTER_CONSUMER_KEY']
        self.consumer_secret = os.environ['TWITTER_CONSUMER_SECRET']
        self.keys = defaultdict(dict)
        self.base_url = 'https://api.twitter.com/1.1/'
        self.MAX_RETRIES = 3
        self.i_lock = threading.Lock()
        self.randomize_keys = True

    def load_keys(self,filename):
        '''Load user key data from a key file. The key file is an ndjson file where each JSON
        object contains the following fields:

            user:                   Screen name of Twitter user
            access_token:           Access token for user
            access_token_secret:    The access token secret
        '''

        keys_file = open(filename,"r")
        with keys_file as f:
            key_data = [line for line in f.read().splitlines() if line != '']
            for obj in key_data:
                auth_key = json.loads(obj)
                screen_name = auth_key['screen_name']
                self.keys[screen_name] = auth_key
                self.keys[screen_name]['endpoint'] = defaultdict(dict)

    def fetch_key(self,endpoint):
        '''This method returns a key that has available capacity (rate-limit). If no keys have
        any available calls left, this function will wait (sleep) until more calls are available
        once a new rate-limit window goes into effect.
        '''

        while True:
            # Scan all keys and reset the rate-limit-remaining to None if rate-limit-reset time is
            # less than the current time.
            keys = list(self.keys.values())
            if self.randomize_keys:
                shuffle(keys)

            for key in keys:
                if endpoint not in key['endpoint']:
                    key['endpoint'][endpoint] = defaultdict(dict)
                    key['endpoint'][endpoint]['rate-limit-reset'] = None
                    key['endpoint'][endpoint]['rate-limit-remaining'] = None
                elif key['endpoint'][endpoint]['rate-limit-reset'] is not None and key['endpoint'][endpoint]['rate-limit-reset'] < int(time.time() - 1):
                    key['endpoint'][endpoint]['rate-limit-remaining'] = None
                    key['endpoint'][endpoint]['rate-limit-reset'] = None

            # Find a key with available calls for the requested endpoint
            for key in keys:
                if key['endpoint'][endpoint]['rate-limit-remaining'] is None or key['endpoint'][endpoint]['rate-limit-remaining'] > 0:
                    if key['endpoint'][endpoint]['rate-limit-remaining'] is not None:
                        self.i_lock.acquire()
                        key['endpoint'][endpoint]['rate-limit-remaining'] -= 1
                        self.i_lock.release()
                    logging.debug("Using auth key {} for endpoint {}.".format(key['screen_name'],endpoint))
                    return key

            # If we get here, there were no keys available to fulfill the request so we'll sleep and try again
            # every second.

            time.sleep(1)

    def get_access_obj(self,access_objs,url):

        while True:
            for obj in access_objs:
                if obj['rate_limit_remaining'][url] > 0 or obj['rate_limit_reset'][url] < int(time.time()):
                    return obj

        time.sleep(1)
        #return access_objs[self.url_counter['url'] % len(self.access_objs)]

    def make_request(self,url,params,headers=None,type='get',user_auth=None):
        '''Make request to Twitter API'''
        retries = self.MAX_RETRIES

        while retries:
            auth_key = self.fetch_key(url)
            logging.info("Using authorization key: {}".format(auth_key['screen_name']))
            auth = OAuth1(self.consumer_key, self.consumer_secret, auth_key['access_token'], auth_key['access_token_secret'])
            if type == 'get':
                r = requests.get(url,params=params,headers=headers,auth=auth)
            elif type == 'post':
                r = requests.post(url,params=params,headers=headers,auth=auth)
            status_code = r.status_code
            response_headers = r.headers
            try:
                rate_limit_remaining = int(response_headers['x-rate-limit-remaining'])
                rate_limit_reset = int(response_headers['x-rate-limit-reset'])
                self.keys[auth_key['screen_name']]['endpoint'][url]['rate-limit-remaining'] = rate_limit_remaining
                self.keys[auth_key['screen_name']]['endpoint'][url]['rate-limit-reset'] = rate_limit_reset
            except:
                pass
            if status_code == 200:
                return r.json()
            elif status_code == 429:
                logging.warning("Rate limit reached for {}. Trying with a different key.".format(auth_key['screen_name']))
            elif status_code == 401:
                return False
            elif status_code == 404:
                logging.warning("Error 404: Unknown Endpoint")
                return False
            else:
                logging.warning("Received status error code: {}".format(status_code))
                retries -= 1
                time.sleep(1)


def statuses_lookup(tm, **kwargs):
    endpoint = '{}statuses/lookup.json'.format(tm.base_url)
    params = defaultdict(dict)
    params['tweet_mode'] = 'extended'
    params.update(kwargs)
    data = tm.make_request(endpoint,kwargs)
    return data




# Example Usage
tm = TokenManager()
tm.load_keys("twitter_access_tokens.ndjson")
data = statuses_lookup(tm,id=[20,21,22,23,24,25,26,27,28,29,30])
print(data)


