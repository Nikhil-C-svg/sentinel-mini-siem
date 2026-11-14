"""Validated detection settings persisted alongside each analysis."""
from dataclasses import dataclass, asdict

@dataclass(frozen=True)
class RuleConfig:
    failure_threshold: int = 5
    failure_minutes: int = 5
    success_threshold: int = 5
    success_minutes: int = 10
    username_threshold: int = 5
    username_minutes: int = 10

    def __post_init__(self):
        for name, value in asdict(self).items():
            if type(value) is not int or not 1 <= value <= 10000:
                raise ValueError(f"{name} must be an integer between 1 and 10000")

    def to_dict(self):
        return asdict(self)
