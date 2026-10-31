#!/usr/bin/env python3
"""Strict post-quantum provider boundary for XAVI-DUO."""
from __future__ import annotations
import importlib.util, subprocess
from mlkem_provider import image_info, self_test as container_self_test

SUITE='xavi-duo-pq2-mlkem1024-xde2'

def provider_status()->dict:
    py={name: bool(importlib.util.find_spec(name)) for name in ('oqs','pqcrypto','kyber_py')}
    try:
        v=subprocess.check_output(['openssl','version'],text=True).strip()
        algs=subprocess.check_output(['openssl','list','-kem-algorithms'],text=True,stderr=subprocess.DEVNULL)
        host_mlkem='ML-KEM' in algs.upper() or 'MLKEM' in algs.upper()
    except Exception:
        v='unavailable'; host_mlkem=False
    container=image_info()
    available=bool(container.get('available')) or host_mlkem or py['oqs'] or py['pqcrypto']
    return {'suite':SUITE,'mlkem_provider_available':available,'preferred_provider':'rootless-openssl-container' if container.get('available') else ('host-openssl' if host_mlkem else None),
            'container_provider':container,'host_openssl':v,'host_openssl_mlkem':host_mlkem,'python_modules':py,'development_fallback':False}

def require_mlkem_provider():
    s=provider_status()
    if not s['mlkem_provider_available']:
        raise RuntimeError('ML-KEM provider unavailable; XAVI-DUO refuses a non-PQ fallback')
    return s

def provider_self_test():
    s=require_mlkem_provider()
    if s['container_provider'].get('available'):
        return container_self_test()
    raise RuntimeError('only the witnessed rootless-container provider is enabled for PQ2 operations')
