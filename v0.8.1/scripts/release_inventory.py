#!/usr/bin/env python3
"""Inventory the exact canonical distributable file set."""
from __future__ import annotations
import hashlib, importlib.util, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('release_file_list',ROOT/'scripts'/'release_file_list.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
rows=list(m.files())
size=sum(p.stat().st_size for _,p in rows)
print(json.dumps({'files':len(rows),'bytes':size,'source':'scripts/release_file_list.py'},sort_keys=True))
for rel,_ in rows: print(rel.as_posix())
