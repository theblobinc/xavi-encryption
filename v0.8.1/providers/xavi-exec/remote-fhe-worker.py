#!/usr/bin/env python3
# Compatibility entrypoint; packaged implementation lives in xavi_duo_remote_worker.
import xavi_duo_remote_worker as _impl
for _name in dir(_impl):
    if not _name.startswith('__'):
        globals()[_name]=getattr(_impl,_name)
if __name__=='__main__': main()
