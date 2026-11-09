
from urllib.parse import unquote

from ..models import APIRequest, DetectionFinding


def detect(request: APIRequest) -> list[DetectionFinding]:
    decoded_path = unquote(request.path)

    if ".." not in decoded_path.split("/"):
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
