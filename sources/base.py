from abc import ABC, abstractmethod
from typing import Iterable, Iterator


class Source(ABC):
    """Base class for a source that turns raw lines into normalized events."""

    name = "unknown"

    @abstractmethod
    def parse(self, line: str) -> dict | None:
        raise NotImplementedError

    def events(self, lines: Iterable[str]) -> Iterator[dict]:
        for line in lines:
            event = self.parse(line)
            if event is not None:
                yield event

LogSource = Source


class SourceRegistry:
    def __init__(self):
        self._sources = {}

    def register(self, name: str, source_class: type[LogSource]):
        self._sources[name] = source_class

    def create(self, name: str, **kwargs) -> LogSource:
        try:
            return self._sources[name](**kwargs)
        except KeyError as exc:
            raise ValueError(f"Unknown log source: {name}") from exc

    def names(self):
        return tuple(self._sources)
