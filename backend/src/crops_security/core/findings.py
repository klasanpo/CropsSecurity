from dataclasses import asdict, dataclass
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "informative"]
Confidence = Literal["confirmed", "high", "medium", "low"]


@dataclass(frozen=True)
class Finding:
    severity: Severity
    confidence: Confidence
    category: str
    indicator: str
    url: str
    file_name: str
    line: int
    snippet: str
    match_text: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)
