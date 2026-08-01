from __future__ import annotations

import pytest

from cryptolab.exceptions import InputValidationError
from cryptolab.sequences.analysis import analyze_binary_sequence


def test_maximum_length_sequence_statistics() -> None:
    result = analyze_binary_sequence("1010011")
    assert result.length == 7
    assert result.zeros == 3
    assert result.ones == 4
    assert result.balanced
    assert result.fundamental_period == 7
    assert result.autocorrelation[0].value == 7
    assert all(item.value == -1 for item in result.autocorrelation[1:])
    assert not result.autocorrelation_truncated


def test_repeated_sequence_period_and_limited_autocorrelation() -> None:
    result = analyze_binary_sequence("101101", max_lag=2)
    assert result.fundamental_period == 3
    assert len(result.autocorrelation) == 3
    assert result.autocorrelation_truncated


def test_cyclic_runs_merge_endpoints() -> None:
    result = analyze_binary_sequence("11011")
    counts = {(run.bit, run.length): run.count for run in result.runs}
    assert counts == {(0, 1): 1, (1, 4): 1}


def test_constant_sequence_and_invalid_lag() -> None:
    result = analyze_binary_sequence("0000")
    assert result.fundamental_period == 1
    assert result.runs[0].length == 4
    with pytest.raises(InputValidationError, match="non-negative"):
        analyze_binary_sequence("01", max_lag=-1)
