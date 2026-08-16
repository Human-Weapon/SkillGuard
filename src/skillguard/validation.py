"""Centralized input validators.

Every public numeric configuration field in SkillGuard must be validated
through these helpers rather than ad-hoc ``isinstance(x, int)`` checks.
``bool`` is a subclass of ``int`` in Python, so a naive ``isinstance(x, int)``
check silently accepts ``True``/``False`` as ``1``/``0``. These helpers reject
that explicitly.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from typing import TypeVar

from skillguard.errors import ValidationError

T = TypeVar("T")


def validate_non_negative_int(value: object, *, name: str, allow_zero: bool = True) -> int:
    """Validate that ``value`` is a plain, non-negative ``int``.

    Rejects ``bool`` (even though ``bool`` is an ``int`` subclass), ``float``
    (including whole-number floats), strings, ``None``, and negative values.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{name} must be an int, got {type(value).__name__}: {value!r}")
    if value < 0:
        raise ValidationError(f"{name} must be non-negative, got {value}")
    if value == 0 and not allow_zero:
        raise ValidationError(f"{name} must be greater than zero, got 0")
    return value


def validate_positive_int(value: object, *, name: str) -> int:
    return validate_non_negative_int(value, name=name, allow_zero=False)


def validate_finite_number(
    value: object, *, name: str, allow_negative: bool = False, allow_zero: bool = True
) -> float:
    """Validate that ``value`` is a finite ``int`` or ``float`` (not ``bool``).

    Rejects ``bool``, ``NaN``, ``+Infinity``, ``-Infinity``, and non-numeric
    types. Use for timeouts, poll intervals, and similar duration fields.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(
            f"{name} must be an int or float, got {type(value).__name__}: {value!r}"
        )
    numeric = float(value)
    if math.isnan(numeric):
        raise ValidationError(f"{name} must not be NaN")
    if math.isinf(numeric):
        raise ValidationError(f"{name} must be finite, got {value}")
    if not allow_negative and numeric < 0:
        raise ValidationError(f"{name} must be non-negative, got {value}")
    if numeric == 0 and not allow_zero:
        raise ValidationError(f"{name} must be greater than zero, got {value}")
    return numeric


def validate_non_empty_str(value: object, *, name: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be a str, got {type(value).__name__}: {value!r}")
    if value == "":
        raise ValidationError(f"{name} must not be empty")
    return value


def materialize_iterable(value: object, *, name: str) -> tuple[T, ...]:
    """Materialize any iterable input into a concrete, immutable tuple.

    Public APIs must call this exactly once on caller-supplied iterables
    before both validating and using the data. Consuming a generator during
    validation and again during use is a documented bug class: this helper
    prevents it by materializing first, so validation and use operate on the
    same concrete sequence.
    """
    if value is None:
        raise ValidationError(f"{name} must not be None")
    if isinstance(value, (str, bytes)):
        raise ValidationError(f"{name} must be an iterable of items, not a bare str/bytes")
    if not isinstance(value, Iterable):
        raise ValidationError(f"{name} must be iterable, got {type(value).__name__}")
    return tuple(value)


def validate_enum_member(value: object, *, name: str, enum_cls: type) -> object:
    try:
        if isinstance(value, enum_cls):
            return value
        return enum_cls(value)
    except ValueError as exc:
        valid = ", ".join(repr(m.value) for m in enum_cls)
        raise ValidationError(f"{name} must be one of [{valid}], got {value!r}") from exc
