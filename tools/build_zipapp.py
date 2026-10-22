"""Build a deterministic source-only application archive."""
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parents[1]
target = root / 'dist' / 'reliqua.pyz'
target.parent.mkdir(exist_ok=True)
files = {str(path.relative_to(root)): path.read_bytes() for path in sorted((root/'reliqua').glob('*.py'))}
files['__main__.py'] = b'from reliqua.cli import main\nraise SystemExit(main())\n'
files['LICENSE'] = (root/'LICENSE').read_bytes()
with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for name, content in sorted(files.items()):
        info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, content)
print(target.name)
