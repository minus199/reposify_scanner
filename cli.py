#!/usr/bin/env python

import logging

def __init_parser():
    import argparse
    parser = argparse.ArgumentParser(description="CVE scanning suite", epilog="Please let me know if you have any questions. I'm aware there is much room for improvments :)")
    parser.add_argument('-i', '--host', required=True)
    parser.add_argument('-p', '--port', required=False)
    parser.add_argument('-d', '--payload', required=False)
    parser.add_argument('-v', '--verbosity-level', default=logging.getLevelName(logging.INFO), choices=logging._levelToName.values())
    parser.add_argument('-s', '--scanner', default='php_http', choices=['php_http', 'php_h','php_websocket', 'php_ws'])
    return parser


# TODO: decide cmd auto by host protocol and maybe some other data

if (__name__ == "__main__"):
    _parser = __init_parser()
    _input_args = _parser.parse_args()

    
    import json
    from lib.services.cve_core_service import CveIndexingService
    from lib.services.scanning_service import ScanningService
    from lib.data.cve_models import CveItem
    
    logging.basicConfig(level=logging._nameToLevel[_input_args.verbosity_level])
    log = logging.getLogger(__name__)
    
    _indexer = CveIndexingService()
    _scanning_service = ScanningService(_indexer)
    _commands = {
        'php_http': _scanning_service.scan_http, 
        'php_h': _scanning_service.scan_http,
        'php_websocket': _scanning_service.scan_websocket,
        'php_ws': _scanning_service.scan_websocket
    }
        
    _cmd = _commands[_input_args.scanner]
    scan_result = _cmd(**_input_args.__dict__)
    
    # print matched cve's for this host
    output = [v[1][0] for v in scan_result.vulnerabilities_list]
    print("\n".join(output))