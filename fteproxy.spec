# -*- mode: python -*-
import os
a = Analysis(['./bin/fteproxy'],
             pathex=['.'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
a.datas += [('fte/defs/20131110.json','fte/defs/20131110.json','DATA')]
if os.name=='nt':
    a.datas += [('bin/fstprint.exe','bin/fstprint.exe','BINARY')]
    a.datas += [('bin/fstcompile.exe','bin/fstcompile.exe','BINARY')]
    a.datas += [('bin/fstminimize.exe','bin/fstminimize.exe','BINARY')]
else:
    a.datas += [('bin/fstprint','bin/fstprint','BINARY')]
    a.datas += [('bin/fstcompile','bin/fstcompile','BINARY')]
    a.datas += [('bin/fstminimize','bin/fstminimize','BINARY')]
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='fteproxy',
          debug=False,
          strip=False,
          upx=False,
          console=True )
