import json
from collections.abc import Iterator
from typing import Any

from ..models import APIRequest


def _strings(value: Any, field: str) -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield field, value
    elif isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and key.isidentifier():
                child_field = f"{field}.{key}"
            else:
                child_field = f"{field}[{json.dumps(str(key))}]"
            yield from _strings(child, child_field)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _strings(child, f"{field}[{index}]")


def request_strings(request: APIRequest) -> Iterator[tuple[str, str]]:
    yield "path", request.path
    yield from _strings(request.query, "query")
    yield from _strings(request.headers, "headers")
    yield from _strings(request.body, "body")
