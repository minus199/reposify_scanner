
from lib.scanners.http_scanner import BaseScanner
from lib.scanners.websocket_scanner import WebsocketScanner
from lib.scanners.http_scanner import HttpScanner

# TODO: implement scanners pool
# TODO: executor service

class ScanningService:
    def __init__(self, indexer):
        self.__indexer = indexer
        
    def scan_http(self, host:str, port:int = None, **_):
        scanner = HttpScanner(self.__indexer) # we can also keep only one instance
        return scanner.scan(host, str(port) if port else port)

    def scan_websocket(self, host: str, payload: str, port: int = None, **_):
        scanner = WebsocketScanner(self.__indexer)
        return scanner.scan(host, str(port) if port else port, payload)