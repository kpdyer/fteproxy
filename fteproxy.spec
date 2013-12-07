# -*- mode: python -*-
import os
import glob
a = Analysis(['./bin/fteproxy'],
             pathex=['.'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='fteproxy',
          debug=False,
          strip=False,
          upx=True,
          console=True )
