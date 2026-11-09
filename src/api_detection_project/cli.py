import argparse
import sys
from codecs import BOM_UTF8
from pathlib import Path

from pydantic import ValidationError
from pydantic_core import from_json

from .detector import analyze_request
from .models import APIRequest


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Analyze one API request from JSON.")
    parser.add_argument(
        "input", nargs="?", default="-", help="UTF-8 JSON file or '-' for standard input"
    )
    args = parser.parse_args(argv)

    try:
        data = sys.stdin.buffer.read() if args.input == "-" else Path(args.input).read_bytes()
    except OSError as exc:
        parser.error(f"could not read input: {exc.strerror}")

    try:
        payload = from_json(data.removeprefix(BOM_UTF8), allow_inf_nan=False)
    except ValueError as exc:
        parser.error(f"invalid JSON: {exc}")

    try:
        request = APIRequest.model_validate(payload)
    except ValidationError as exc:
        errors = exc.errors(include_input=False, include_url=False)
        details = ", ".join(f"{error['loc']!r} {error['msg']}" for error in errors)
        parser.error(f"invalid API request: {details}")

    print(analyze_request(request).model_dump_json(indent=2, ensure_ascii=True))
