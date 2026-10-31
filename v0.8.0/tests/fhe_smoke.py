#!/usr/bin/env python3
import json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from xavi_duo_compute import tfhe_local_boolean_smoke
if __name__=='__main__': print(json.dumps(tfhe_local_boolean_smoke(),sort_keys=True))
