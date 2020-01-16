from lib.data.cve_models import CveItem
from typing import List


class ServerMetadata:
    def __init__(self, host, runtime, runtime_v = None):
        self.host = host
        self.runtime = runtime.lower()
        try:
            self.runtime_v = runtime_v.split("-")[0].lower() # try to get simple semver 
        except:
            self.runtime_v = runtime_v
            
        try:
            self.major_runtime_v = "*" #self.runtime_v.split(".")[0]
        except:
            self.major_runtime_v = "*"
            
            
    @staticmethod
    def find_header_case_insensitive(headers, header_name: str):
        return headers.get(header_name, headers.get(header_name.lower(), None))
        
    @staticmethod
    def parse_from_raw_headers(headers, req_url):
        match_header = lambda header: ServerMetadata.find_header_case_insensitive(headers, header) 
        h = match_header('X-Powered-By')
        h = (h if h else match_header("Server"))
            
        try:
            return ServerMetadata(req_url, *h.split("/"))
        except Exception as e:
            return None


class ScanningResponse:
    def __init__(self, server_meta: ServerMetadata, vulnerabilities_list: List[CveItem], **extras):
        self.server_meta = server_meta
        self.vulnerabilities_list = vulnerabilities_list
        self.extras = extras
