from dataclasses import dataclass, field


@dataclass
class VolumeProbe:
    kind: str
    display_name: str
    is_encrypted: bool = False
    details: dict = field(default_factory=dict)


@dataclass
class UnlockPlan:
    kind: str
    command: str | None
    details: dict = field(default_factory=dict)
