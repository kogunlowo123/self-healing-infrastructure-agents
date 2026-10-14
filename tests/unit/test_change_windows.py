"""Change calendar: weekly windows across time zones, midnight crossing, freezes."""

from __future__ import annotations

from datetime import UTC, datetime, time

import pytest
from pydantic import ValidationError

from self_healing_infrastructure_agents.governance.change_windows import (
    ChangeCalendar,
    Freeze,
    WeeklyWindow,
)
from tests.conftest import ROOT


@pytest.fixture
def calendar() -> ChangeCalendar:
    return ChangeCalendar.from_file(ROOT / "policies" / "change-windows.yaml")


def utc(*args: int) -> datetime:
    return datetime(*args, tzinfo=UTC)


class TestShippedCalendar:
    def test_production_weekday_window_in_new_york(self, calendar: ChangeCalendar) -> None:
        # Wednesday 14:00 UTC is 10:00 EDT.
        assert calendar.status("production", utc(2026, 10, 14, 14, 0)).open
        # Wednesday 12:00 UTC is 08:00 EDT: before the window opens.
        closed = calendar.status("production", utc(2026, 10, 14, 12, 0))
        assert not closed.open
        assert not closed.frozen
        assert closed.next_open == utc(2026, 10, 14, 13, 0)

    def test_sunday_window_crosses_midnight(self, calendar: ChangeCalendar) -> None:
        assert calendar.status("production", utc(2026, 10, 18, 23, 30)).open  # Sunday night
        assert calendar.status("production", utc(2026, 10, 19, 1, 30)).open  # Monday early
        assert not calendar.status("production", utc(2026, 10, 19, 2, 30)).open

    def test_freeze_overrides_windows(self, calendar: ChangeCalendar) -> None:
        # Wednesday 25 November 2026, 10:00 EST: inside a window but frozen.
        status = calendar.status("production", utc(2026, 11, 25, 15, 0))
        assert status.frozen
        assert not status.open
        assert "Thanksgiving" in status.reason
        assert status.next_open is not None
        assert status.next_open >= utc(2026, 12, 1)

    def test_staging_freeze_and_unlisted_environments(self, calendar: ChangeCalendar) -> None:
        assert calendar.status("staging", utc(2026, 12, 21, 12, 0)).frozen
        assert calendar.status("staging", utc(2026, 11, 25, 12, 0)).open  # prod-only freeze
        development = calendar.status("development", utc(2026, 10, 18, 3, 0))
        assert development.open
        assert development.reason == "no change window configured"


class TestValidation:
    def test_unknown_day_and_zone(self) -> None:
        with pytest.raises(ValidationError, match="unknown days"):
            WeeklyWindow(days=("funday",), start=time(1), end=time(2))
        with pytest.raises(ValidationError):
            WeeklyWindow(days=("mon",), start=time(1), end=time(2), timezone="Mars/Olympus")
        with pytest.raises(ValidationError, match="differ"):
            WeeklyWindow(days=("mon",), start=time(1), end=time(1))

    def test_freeze_for_every_environment(self) -> None:
        freeze = Freeze(start=utc(2026, 1, 1), end=utc(2026, 1, 2), reason="audit")
        assert freeze.applies("anything", utc(2026, 1, 1, 12))
        assert not freeze.applies("anything", utc(2026, 1, 2, 0))

    def test_never_open_returns_no_next_window(self) -> None:
        calendar = ChangeCalendar(
            name="c",
            version="1",
            windows={"production": ()},
            freezes=(Freeze(start=utc(2026, 1, 1), end=utc(2027, 1, 1), reason="forever"),),
        )
        status = calendar.status("production", utc(2026, 6, 1))
        assert status.frozen
        assert status.next_open is None
        # Environments without windows reopen when the freeze ends.
        assert calendar.status("dev", utc(2026, 6, 1)).next_open == utc(2027, 1, 1)
