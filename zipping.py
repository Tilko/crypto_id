from pathlib import Path
import zipfile


def zip_folder(src_dir: str | Path, zip_path: str | Path) -> None:
    src_dir = Path(src_dir).resolve()
    zip_path = Path(zip_path).resolve()

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for path in src_dir.rglob("*"):
            # archive name = chemin relatif dans le zip
            arcname = path.relative_to(src_dir)
            z.write(path, arcname)
