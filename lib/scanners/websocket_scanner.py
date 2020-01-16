import asyncio
import websockets
import logging

from lib.scanners.base_scanner import BaseScanner
from lib.data.scanning_responses import ScanningResponse, ServerMetadata
from lib.services.cve_core_service import CveIndexingService

log = logging.getLogger(__name__)

class WebsocketScanner(BaseScanner):
    def __init__(self, indexer: CveIndexingService, description=""):
        super().__init__(description)
        self.__indexer = indexer

    async def __scan(self, host, port, payload) -> ScanningResponse:
        async with websockets.connect(self._gen_uri(host, port)) as websocket:
            log.debug(f"starting scan to {host}")
            await websocket.send(payload)
            response = await websocket.recv()
            log.debug(f"scan to {host} completed")
            
            server_meta = self._parse_server_meta(websocket.response_headers, host)
            cve = self.__indexer.find_by_server_meta(server_meta)
            return ScanningResponse(server_meta, cve, response_body=response)

    def scan(self, host, port, payload, **_) -> ScanningResponse:
        return asyncio.get_event_loop().run_until_complete(self.__scan(host, port, payload))
