from google.cloud import logging


class Gcp_log_rertriever:
    def __init__(self, client):
        self.client = client