import requests
import datetime


class Github:
    def __init__(self, access_token, organization=None, enterprise=None):
        self.headers = {
            'Authorization': f'token {access_token}',
            'Accept': 'application/vnd.github+json',
            'X-Real-IP': 'true'
        }
        self.organization = organization
        self.enterprise = enterprise
