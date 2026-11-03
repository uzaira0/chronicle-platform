"""Replay the release client's synthetic enrollment and upload through the public edge."""
from dataclasses import dataclass
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

API_KEY_HEADER = 'X-Api-Key'
CANARY_FILE_SETTING = 'CHRONICLE_VERIFY_MOBILE_CANARY'
CANARY_ROUTES = {'enrollment': '/enroll', 'collection_ack': '/android/collection-ack', 'upload': '/android/sensors'}


@dataclass(frozen=True)
class CanaryRequest:
    url: str
    body: object
    headers: dict

    def __post_init__(self):
        if (not isinstance(self.url, str) or not isinstance(self.body, (dict, list))
                or not isinstance(self.headers, dict)
                or any(not isinstance(key, str) or not isinstance(value, str) for key, value in self.headers.items())):
            raise ValueError('invalid synthetic request')


def load_canary(path, public):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
        raise ValueError('synthetic mobile canary must be a regular private file')
    document = json.loads(path.read_text())
    requests = {}
    for name, suffix in CANARY_ROUTES.items():
        request = CanaryRequest(**document[name])
        origin = urlsplit(request.url)
        if (origin.scheme + '://' + origin.netloc != public or origin.query or origin.fragment
                or not re.fullmatch(r'/chronicle/v4/study/[0-9a-f-]{36}/participant/smoke-[a-z0-9]+' + re.escape(suffix), origin.path)):
            raise ValueError('canary must use synthetic mobile identities on the public origin')
        requests[name] = request
    return requests


def verify_canary(path, public, send):
    requests = load_canary(path, public)
    enrolled = send(requests['enrollment'])
    if not isinstance(enrolled, dict) or not enrolled.get('apiKey') or enrolled['apiKey'] != requests['upload'].headers.get(API_KEY_HEADER):
        raise ValueError('synthetic enrollment did not replay its device credential')
    send(requests['collection_ack'])
    batch = requests['upload'].body
    if not isinstance(batch, list) or not batch or send(requests['upload']) != len(batch):
        raise ValueError('synthetic upload did not acknowledge its batch')
