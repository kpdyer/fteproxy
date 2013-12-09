# -*- mode: python -*-
a = Analysis(['./bin/fteproxy'],
             pathex=['.'],
             hiddenimports=['fte.cDFA'],
             hookspath=None,
             runtime_hooks=None,
            )
excludeModules = [
'audioop',
'bz2',
'_ssl',
'libssl.so.1.0.0',
'libcrypto.so.1.0.0',
'_codecs_jp',
'_codecs_cn',
'_codecs_tw',
'_codecs_hk',
'_codecs_kr',
'_multibytecodec',
]
for val in a.binaries:
    if val[0] in excludeModules:
        a.binaries.remove(val)
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
