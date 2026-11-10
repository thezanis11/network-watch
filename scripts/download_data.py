"""Fetch only labeled text logs and documentation, with original checksums."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RECORD = 'https://zenodo.org/api/records/21027042'


def main():
    folder = ROOT / 'data/raw'
    folder.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(RECORD, timeout=90) as response:
        record = json.load(response)
    selected = {'zeek.zip', 'labels.zip', 'README.md', 'CTU-IDSEVAL-6-summary.csv'}
    manifest = dict(record=RECORD, doi=record['metadata']['doi'], license=record['metadata'].get('license'), files=[])
    for item in record['files']:
        if item['key'] not in selected:
            continue
        path = folder / item['key']
        if not path.exists() or path.stat().st_size != item['size']:
            with urllib.request.urlopen(item['links']['self'], timeout=120) as response:
                path.write_bytes(response.read())
        with path.open('rb') as source:
            digest = hashlib.file_digest(source, 'md5').hexdigest()
        if f'md5:{digest}' != item['checksum']:
            raise ValueError(f'Checksum mismatch: {item["key"]}')
        manifest['files'].append(dict(name=item['key'], bytes=item['size'], checksum=item['checksum'], url=item['links']['self']))
        print(f'Verified {item["key"]}: {item["size"]:,} bytes', flush=True)
    (folder / 'provenance.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
