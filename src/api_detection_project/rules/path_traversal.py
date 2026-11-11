
from urllib.parse import unquote

from ..models import APIRequest, DetectionFinding


def detect(request: APIRequest) -> list[DetectionFinding]:
    decoded_path = request.path
    for _ in range(2):
        next_path = unquote(decoded_path)
        if next_path == decoded_path:
            break
        decoded_path = next_path

    if ".." not in decoded_path.replace("\\", "/").split("/"):
        return []

    return [
        DetectionFinding(
            rule_id="PATH_001",
            technique="path_traversal",
            signal="parent_directory_segment",
            field="path",
            explanation="Path contains parent-directory navigation.",
            evidence={"decoded_path": decoded_path}
        )
    ]
