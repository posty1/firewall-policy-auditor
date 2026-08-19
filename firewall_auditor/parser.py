import csv
from pathlib import Path

from .models import Rule


REQUIRED = {"name", "source", "destination", "service", "action", "enabled", "owner", "expires"}


def _items(value: str) -> tuple[str, ...]:
    return tuple(part.strip().lower() for part in value.split(";") if part.strip()) or ("any",)


def load_rules(path: str | Path) -> list[Rule]:
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing CSV columns: {', '.join(sorted(missing))}")
        return [
            Rule(
                position=index,
                name=row["name"].strip(),
                source=_items(row["source"]),
                destination=_items(row["destination"]),
                service=_items(row["service"]),
                action=row["action"].strip().lower(),
                enabled=row["enabled"].strip().lower() in {"true", "yes", "1", "enabled"},
                owner=row["owner"].strip(),
                expires=row["expires"].strip(),
            )
            for index, row in enumerate(reader, start=1)
        ]
