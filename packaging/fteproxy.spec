# -*- mode: python -*-
a = Analysis(['./bin/fteproxy'],
             pathex=['/home/vagrant/fteproxy'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
a.datas += [('fte/defs/20131110.json','fte/defs/20131110.json','DATA')]
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='fteproxy',
          debug=False,
          strip=True,
          upx=True,
          console=True )
