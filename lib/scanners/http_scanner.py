import requests
from lib.scanners.base_scanner import BaseScanner
from lib.services.cve_core_service import CveIndexingService
from lib.data.scanning_responses import ScanningResponse
import logging

log = logging.getLogger(__name__)

class HttpScanner(BaseScanner):
    def __init__(self, indexer: CveIndexingService, predicates = []):
        self.__predicates = predicates
        self.__indexer = indexer

    def scan(self, host, port=None, **_) -> ScanningResponse:
        log.debug(f"starting scan to {host}")
        r = requests.get(self._gen_uri(host, port))
        log.debug(f"scan to {host} complete")
            
        server_meta = self._parse_server_meta(r.headers, r.url)
        cve = self.__indexer.find_by_server_meta(server_meta)
        return ScanningResponse(server_meta, cve, response_body=r.content)
