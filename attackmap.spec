# -*- mode: python ; coding: utf-8 -*-
# PyInstaller one-file spec — builds a self-contained `attackmap` executable
# (no system Python needed). Cross-platform: same spec on Linux and Windows.
#   pyinstaller attackmap.spec   ->   dist/attackmap (Linux)  /  dist/attackmap.exe (Windows)
#
# world.geojson is bundled as data and found at runtime via app._resource()
# (sys._MEIPASS). geo.py / sources.py are picked up automatically as imports.

a = Analysis(
    ['app.py'],
    pathex=['.'],
    binaries=[],
    datas=[('world.geojson', '.')],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'unittest', 'pydoc'],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='attackmap',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
