from lib.data.scanning_responses import ServerMetadata
from lib.data.cve_models import CveItem, Node, CpeMatch
from typing import List, Set
from lib.services.cache_provider import cache_provider
import logging

log = logging.getLogger(__name__)


class CveIndexingService:
    def find_by_runtime_version(self, rt: str, v: str) -> List[CveItem]:
        cpe_criteria_ = 'cpe:2.3:a' + (f':{rt}:' if rt else '') + (v if v else '')
        # TODO: Search with wild cards in cpe
        
        log.info(f"Searching for {cpe_criteria_}")
        acc = []
        for item in cache_provider():
            matches = list(self.match_cpe(item, cpe_criteria_))
            if (len(matches) > 0):
                acc.append([item, matches])
        
        return acc

    def find_by_server_meta(self, server_meta: ServerMetadata) -> List[CveItem]:
        return self.find_by_runtime_version(server_meta.runtime, server_meta.major_runtime_v)

    @staticmethod
    def match_cpe(item, cpe_criteria):
        return filter(lambda cpe: cpe.startswith(cpe_criteria), item.list_exploites()['cpe'])
