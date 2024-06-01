# -*- mode: python ; coding: utf-8 -*-

import os
import pykakasi

pykakasi_path = os.path.dirname(pykakasi.__file__)

block_cipher = None

a = Analysis(
    ['squirrel.py'],
    pathex=['.', '_bottle_websocket_', '_bottle_websocket_\\*.py', '_EEL_', '_EEL_\\*.py', 'lib', 'lib\\*.py', 'nutFs', 'nutFs\\*.py', 'Fs', 'Fs\\*.py', 'manager', 'manager\\*.py', 'mtp', 'mtp\\*.py', 'Drive', 'Drive\\*.py'],
    binaries=[],
    datas=[('keys.txt', '.'), (pykakasi_path, 'pykakasi')],
    hiddenimports=['pykakasi'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['dist','build'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)
pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher
)
exe = EXE(
    pyz,
    a.scripts, 
    [],
    exclude_binaries=True,
    name='squirrel',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='squirrel.ico',
    version='version.txt'
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas, 
    strip=False,
    upx=True,
    upx_exclude=[],
    name='squirrel'
)