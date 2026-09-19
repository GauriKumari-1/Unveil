from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class Event(BaseModel):
    id: str
    timestamp: datetime
    source: str
    event_type: str
    user: str = ""
    host: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class IOC(BaseModel):
    type: str
    value: str
    source_event_id: str


class Alert(BaseModel):
    id: str
    severity: str
    type: str
    reason: str
    events: list[str] = Field(default_factory=list)
    score: int = 0
    breakdown: list[dict[str, Any]] = Field(default_factory=list)
    timestamp: datetime | None = None


class CaseResult(BaseModel):
    case_id: str
    files: list[dict[str, str]] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
