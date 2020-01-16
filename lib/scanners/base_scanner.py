from uuid import uuid4
from abc import ABC, abstractmethod
from lib.data.scanning_responses import ScanningResponse, ServerMetadata

class BaseScanner(ABC):
    # @abstractmethod
    def __init__(self, description=""):
        self.id = uuid4  
        self.description = description
    
    def _gen_uri(self, host, port):
        return host if port is None else f'{host}:{port}'
    
    def _parse_server_meta(self, headers, req_url):
        return ServerMetadata.parse_from_raw_headers(headers, req_url)

    @abstractmethod
    def scan(self, host, port, **additional_args) -> ScanningResponse:
        pass
