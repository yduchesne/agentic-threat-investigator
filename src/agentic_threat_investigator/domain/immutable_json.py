# SPDX-License-Identifier: AGPL-3.0-only
"""Deeply immutable representations for JSON domain values."""

import math
from collections.abc import Mapping
from typing import Any, Self, TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None


class FrozenDict(dict[str, Any]):
    """A dictionary that rejects every mutation after construction."""

    def __init__(self, values: Mapping[str, Any] | None = None) -> None:
        dict.__init__(self, values or {})

    @staticmethod
    def _immutable() -> None:
        """Reject an attempted mutation."""
        raise TypeError("immutable JSON mappings cannot be modified")

    def __setitem__(self, key: str, value: Any) -> None:
        self._immutable()

    def __delitem__(self, key: str) -> None:
        self._immutable()

    def clear(self) -> None:
        self._immutable()

    def pop(self, key: str, default: Any = None) -> Any:
        _ = key, default
        self._immutable()

    def popitem(self) -> tuple[str, Any]:
        self._immutable()
        raise AssertionError("unreachable")

    def setdefault(self, key: str, default: Any = None) -> Any:
        _ = key, default
        self._immutable()

    def update(self, *args: Any, **kwargs: Any) -> None:
        _ = args, kwargs
        self._immutable()

    def __ior__(self, value: Any) -> Self:  # type: ignore[override,misc]
        self._immutable()
        raise AssertionError("unreachable")

    def __copy__(self) -> "FrozenDict":
        """Immutable values can safely share their representation."""
        return self

    def __deepcopy__(self, _memo: dict[int, object]) -> "FrozenDict":
        """Immutable values can safely share their representation."""
        return self


ImmutableJson: TypeAlias = JsonScalar | tuple["ImmutableJson", ...] | FrozenDict


def freeze_json(value: Any) -> ImmutableJson:
    """Validate a JSON value and return a recursively immutable snapshot."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, ImmutableJson] = {}
        for key, nested in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            frozen[key] = freeze_json(nested)
        return FrozenDict(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(freeze_json(item) for item in value)
    raise ValueError(f"unsupported JSON value: {type(value).__name__}")


def freeze_mapping(value: Mapping[str, Any]) -> FrozenDict:
    """Validate a JSON object and return its immutable snapshot."""
    frozen = freeze_json(value)
    if not isinstance(frozen, FrozenDict):  # pragma: no cover - type narrowing
        raise TypeError("expected a JSON object")
    return frozen


def thaw_json(value: Any) -> Any:
    """Return a mutable JSON-compatible copy for persistence/transport."""
    if isinstance(value, Mapping):
        return {key: thaw_json(nested) for key, nested in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value
