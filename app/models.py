from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Role = Literal["primary", "supporting"]


@dataclass(frozen=True)
class TechniqueSource:
    source_id: str
    role: Role
    why: str
    evidence: str


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    sources: tuple[TechniqueSource, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    category: str
    cost: int
    description: str


@dataclass(frozen=True)
class Environment:
    id: str
    name: str
    enabled_sources: tuple[str, ...]
    description: str = ""


@dataclass(frozen=True)
class Recommendation:
    source_id: str
    source_name: str
    gain: float
    gain_points: float
    cost: int
    score: float
    new_coverage: float
    why: tuple[str, ...]


@dataclass(frozen=True)
class Scenario:
    name: str
    sources: tuple[str, ...]
    coverage: float
    cost: int
