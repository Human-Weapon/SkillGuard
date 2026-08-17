"""Bool/NaN/Infinity/negative sweeps and iterable-materialization tests for
every centralized validator. Every public numeric config field routes
through these, so bugs here are bugs everywhere (spec sections 16/112/113)."""

from __future__ import annotations

import math

import pytest

from skillguard.errors import ValidationError
from skillguard.validation import (
    materialize_iterable,
    validate_finite_number,
    validate_non_empty_str,
    validate_non_negative_int,
    validate_positive_int,
)


class TestValidateNonNegativeInt:
    def test_accepts_zero_by_default(self):
        assert validate_non_negative_int(0, name="x") == 0

    def test_accepts_positive(self):
        assert validate_non_negative_int(5, name="x") == 5

    def test_rejects_true(self):
        with pytest.raises(ValidationError):
            validate_non_negative_int(True, name="x")

    def test_rejects_false(self):
        with pytest.raises(ValidationError):
            validate_non_negative_int(False, name="x")

    def test_rejects_negative(self):
        with pytest.raises(ValidationError):
            validate_non_negative_int(-1, name="x")

    def test_rejects_float(self):
        with pytest.raises(ValidationError):
            validate_non_negative_int(1.0, name="x")

    def test_rejects_str(self):
        with pytest.raises(ValidationError):
            validate_non_negative_int("10", name="x")

    def test_rejects_none(self):
        with pytest.raises(ValidationError):
            validate_non_negative_int(None, name="x")

    def test_zero_rejected_when_disallowed(self):
        with pytest.raises(ValidationError):
            validate_non_negative_int(0, name="x", allow_zero=False)


class TestValidatePositiveInt:
    def test_rejects_zero(self):
        with pytest.raises(ValidationError):
            validate_positive_int(0, name="x")

    def test_rejects_bool(self):
        with pytest.raises(ValidationError):
            validate_positive_int(True, name="x")


class TestValidateFiniteNumber:
    def test_accepts_int_and_float(self):
        assert validate_finite_number(3, name="x") == 3.0
        assert validate_finite_number(3.5, name="x") == 3.5

    def test_rejects_bool(self):
        with pytest.raises(ValidationError):
            validate_finite_number(True, name="x")

    def test_rejects_nan(self):
        with pytest.raises(ValidationError):
            validate_finite_number(math.nan, name="x")

    def test_rejects_positive_infinity(self):
        with pytest.raises(ValidationError):
            validate_finite_number(math.inf, name="x")

    def test_rejects_negative_infinity(self):
        with pytest.raises(ValidationError):
            validate_finite_number(-math.inf, name="x", allow_negative=True)

    def test_rejects_negative_by_default(self):
        with pytest.raises(ValidationError):
            validate_finite_number(-1.0, name="x")

    def test_allows_negative_when_requested(self):
        assert validate_finite_number(-1.0, name="x", allow_negative=True) == -1.0

    def test_rejects_zero_when_disallowed(self):
        with pytest.raises(ValidationError):
            validate_finite_number(0, name="x", allow_zero=False)

    def test_rejects_str(self):
        with pytest.raises(ValidationError):
            validate_finite_number("1.0", name="x")


class TestValidateNonEmptyStr:
    def test_rejects_empty(self):
        with pytest.raises(ValidationError):
            validate_non_empty_str("", name="x")

    def test_rejects_non_str(self):
        with pytest.raises(ValidationError):
            validate_non_empty_str(123, name="x")

    def test_accepts_nonempty(self):
        assert validate_non_empty_str("ok", name="x") == "ok"


class TestMaterializeIterable:
    def test_materializes_list(self):
        assert materialize_iterable([1, 2, 3], name="x") == (1, 2, 3)

    def test_materializes_generator_exactly_once(self):
        def gen():
            yield 1
            yield 2

        result = materialize_iterable(gen(), name="x")
        assert result == (1, 2)
        # a second read of the *same materialized tuple* must still work --
        # this proves we're not holding a spent generator.
        assert tuple(result) == (1, 2)

    def test_rejects_none(self):
        with pytest.raises(ValidationError):
            materialize_iterable(None, name="x")

    def test_rejects_bare_str(self):
        with pytest.raises(ValidationError):
            materialize_iterable("abc", name="x")

    def test_rejects_non_iterable(self):
        with pytest.raises(ValidationError):
            materialize_iterable(42, name="x")

    def test_empty_iterable_is_valid(self):
        assert materialize_iterable([], name="x") == ()
