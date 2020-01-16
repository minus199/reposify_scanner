from lib.data.scanning_responses import ServerMetadata
from lib.data.cve_models import CveItem, Node, CpeMatch
from common.once import run_once

from typing import List, Set
import logging
import json

_CACHE_STORE_URI = "./resources/data/cve.json"

log = logging.getLogger(__name__)

# TODO: proper db for indexing and caching_
@run_once
def cache_provider():
    log.debug("cache was not yet loaded, loading from disk...")
    with open(_CACHE_STORE_URI) as fh:
        c = [CveItem.build(raw_item)
            for raw_item in json.load(fh).get("CVE_Items")]
        log.debug("cache was loaded from disk.")
        return c