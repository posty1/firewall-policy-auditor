from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Rule:
    position: int
    name: str
    source: tuple[str, ...]
    destination: tuple[str, ...]
    service: tuple[str, ...]
    action: str
    enabled: bool
    owner: str
    expires: str


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    check: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)
