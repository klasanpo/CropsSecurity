from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class ScanParameters(BaseModel):
    max_urls: int = Field(default=200, ge=1, le=500)
    depth: int = Field(default=2, ge=0, le=5)
    timeout_seconds: int = Field(default=10, ge=2, le=60)
    max_resource_bytes: int = Field(default=2_000_000, ge=100_000, le=10_000_000)
    include_external: bool = False
    verify_tls: bool = True
    custom_words: list[str] = Field(default_factory=list, max_length=30)
    context_chars: int = Field(default=1500, ge=80, le=1500)

    @field_validator("custom_words")
    @classmethod
    def normalize_custom_words(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            word = value.strip()
            if word and len(word) <= 80 and word not in normalized:
                normalized.append(word)
        return normalized


class ScanCreate(BaseModel):
    module_id: str
    target: str = Field(min_length=3, max_length=2048)
    authorized: Literal[True]
    parameters: ScanParameters = Field(default_factory=ScanParameters)


class ScanBatchCreate(BaseModel):
    module_id: str
    targets: list[str] = Field(min_length=1, max_length=100)
    authorized: Literal[True]
    label: str | None = Field(default=None, max_length=120)
    parameters: ScanParameters = Field(default_factory=ScanParameters)

    @field_validator("targets")
    @classmethod
    def normalize_targets(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            target = value.strip()
            if target and not target.startswith("#") and target not in normalized:
                normalized.append(target)
        if not normalized:
            raise ValueError("Informe ao menos um alvo válido.")
        return normalized


class ScanResponse(BaseModel):
    id: str
    module_id: str
    target: str
    status: str
    progress: int
    phase: str
    parameters: dict[str, Any]
    pages_scanned: int
    findings_count: int
    error: str | None
    created_at: str
    started_at: str | None
    finished_at: str | None
    cancel_requested: bool
    batch_id: str | None = None
