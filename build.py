import os
import shutil
import zipapp
import zipfile

WORKSPACE = os.path.abspath(os.path.dirname(__file__))
SOURCE_DIR = os.path.join(WORKSPACE, "expemu")
SOURCE_EXEC = "" # has __main__.py, ignore
FILE_LIST = {
    "README.md": "README.md",
    "requirements.txt": "requirements.txt",
    # optional files below
    "rootfs/fonts/ufont8.ubmf": "rootfs/fonts/ufont8.ubmf",
    "rootfs/fonts/ufont16.ubmf": "rootfs/fonts/ufont16.ubmf",
    "rootfs/vgp/release.wasm": "rootfs/vgp/release.wasm",
    "exp/CoreMark.exp": "exp/CoreMark.exp",
    "exp/useless.exp": "exp/useless.exp",
    "exp/wasm3CoreMark.exp": "exp/wasm3CoreMark.exp",
}

DIST_INTERPRETER = "/usr/bin/env python3"
DIST_DIR = os.path.join(WORKSPACE, "dist")
DIST_EXEC_NAME = "expemu.pyz"
DIST_NAME = "EXPEmulator.zip"

def purge_cache(path):
    # walk all files
    for file_name in os.listdir(path):
        file_name: str = file_name
        abs_path = os.path.join(path, file_name)
        if file_name == "__pycache__" or file_name.endswith(".dist-info"):
            print(abs_path)
            # delete `__pycache__`
            shutil.rmtree(abs_path)
        elif os.path.isdir(abs_path):
            # call for subdir
            purge_cache(abs_path)

if __name__ == "__main__":
    os.chdir(WORKSPACE)
    # purge __pycache__ and .dist-info
    purge_cache(SOURCE_DIR)
    # clean dist dir
    if os.path.exists(DIST_DIR):
        shutil.rmtree(DIST_DIR)
    os.mkdir(DIST_DIR)
    # zipapp
    zipapp.create_archive(
        SOURCE_DIR,
        os.path.join(DIST_DIR, DIST_EXEC_NAME),
        DIST_INTERPRETER,
        SOURCE_EXEC,
        compressed=True,
    )
    # zip
    zf = zipfile.ZipFile(os.path.join(DIST_DIR, DIST_NAME), "w", compression=zipfile.ZIP_DEFLATED)
    zf.write(os.path.join(DIST_DIR, DIST_EXEC_NAME), DIST_EXEC_NAME)
    for file in FILE_LIST.keys():
        if os.path.exists(file):
            zf.write(file, FILE_LIST[file])
        else:
            print(f"Warning: '{file}' not exist.")
    zf.close()
