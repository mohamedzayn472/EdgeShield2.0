"""Closed schema: no user strings cross into Llama."""
from dataclasses import dataclass
import math
from .indicators import DESCRIPTIONS

BANDS = ("LEGITIMATE", "UNCERTAIN", "SCAM")


@dataclass(frozen=True)
class Evidence:
    band: str
    score: float
    indicators: tuple[str, ...]
    schema_version: int = 1

    def __post_init__(self):
        if type(self.band) is not str or self.band not in BANDS:
            raise ValueError("Invalid decision band")
        if type(self.score) not in (int, float) or not math.isfinite(self.score) or not 0 <= self.score <= 1:
            raise ValueError("Invalid detector score")
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("Unsupported evidence schema")
        if type(self.indicators) is not tuple or len(self.indicators) > len(DESCRIPTIONS):
            raise ValueError("Invalid indicators")
        if any(type(i) is not str or i not in DESCRIPTIONS for i in self.indicators):
            raise ValueError("Unknown indicator")
        if len(set(self.indicators)) != len(self.indicators):
            raise ValueError("Duplicate indicators")

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != {"band", "score", "indicators", "schema_version"}:
            raise ValueError("Evidence fields are not allowlisted")
        if type(value["indicators"]) is not list:
            raise ValueError("Invalid indicator list")
        return cls(value["band"], value["score"], tuple(value["indicators"]), value["schema_version"])

    def validated(self):
        self.__post_init__()
        return self
