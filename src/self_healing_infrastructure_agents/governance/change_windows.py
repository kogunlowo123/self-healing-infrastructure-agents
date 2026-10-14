"""Change calendar: recurring weekly windows per environment and freeze periods.

Windows are local times in an IANA time zone and may cross midnight
(``start`` after ``end``). A freeze overrides every window. All checks use
the injected clock.
"""

from __future__ import annotations

from datetime import datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


class WeeklyWindow(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    days: tuple[str, ...] = Field(min_length=1, description="Days the window opens on")
    start: time
    end: time
    timezone: str = "UTC"

    @field_validator("days")
    @classmethod
    def _days(cls, days: tuple[str, ...]) -> tuple[str, ...]:
        lowered = tuple(d.lower()[:3] for d in days)
        unknown = [d for d in lowered if d not in _DAYS]
        if unknown:
            raise ValueError(f"unknown days {unknown}")
        return lowered

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown time zone {value!r}") from exc
        return value

    @model_validator(mode="after")
    def _non_empty(self) -> WeeklyWindow:
        if self.start == self.end:
            raise ValueError("window start and end must differ")
        return self

    def contains(self, at: datetime) -> bool:
        local = at.astimezone(ZoneInfo(self.timezone))
        day = _DAYS[local.weekday()]
        previous_day = _DAYS[(local.weekday() - 1) % 7]
        now = local.time()
        if self.start < self.end:
            return day in self.days and self.start <= now < self.end
        # Crosses midnight: opened today after start, or opened yesterday and not yet ended.
        return (day in self.days and now >= self.start) or (
            previous_day in self.days and now < self.end
        )


class Freeze(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    start: AwareDatetime
    end: AwareDatetime
    reason: str = Field(min_length=3)
    environments: tuple[str, ...] = Field(default=(), description="Empty means every environment")

    def applies(self, environment: str, at: datetime) -> bool:
        in_scope = not self.environments or environment in self.environments
        return in_scope and self.start <= at < self.end


class WindowStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    open: bool
    frozen: bool
    reason: str
    next_open: datetime | None = None


class ChangeCalendar(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    version: str
    # Environments without windows are always open (e.g. development).
    windows: dict[str, tuple[WeeklyWindow, ...]] = Field(default_factory=dict)
    freezes: tuple[Freeze, ...] = ()

    @classmethod
    def from_file(cls, path: Path) -> ChangeCalendar:
        return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))

    def status(self, environment: str, at: datetime) -> WindowStatus:
        for freeze in self.freezes:
            if freeze.applies(environment, at):
                return WindowStatus(
                    open=False,
                    frozen=True,
                    reason=f"change freeze: {freeze.reason}",
                    next_open=self._next_open(environment, freeze.end),
                )
        windows = self.windows.get(environment)
        if windows is None:
            return WindowStatus(open=True, frozen=False, reason="no change window configured")
        for window in windows:
            if window.contains(at):
                return WindowStatus(open=True, frozen=False, reason="inside change window")
        return WindowStatus(
            open=False,
            frozen=False,
            reason="outside change window",
            next_open=self._next_open(environment, at),
        )

    def _next_open(self, environment: str, after: datetime) -> datetime | None:
        """First minute at or after ``after`` that is inside a window and not frozen."""
        windows = self.windows.get(environment)
        if windows is None:
            return after if not self._frozen(environment, after) else None
        candidate = after.replace(second=0, microsecond=0)
        for _ in range(8 * 24 * 4):  # scan up to 8 days in 15-minute steps
            if any(w.contains(candidate) for w in windows) and not self._frozen(
                environment, candidate
            ):
                return candidate
            candidate += timedelta(minutes=15)
        return None

    def _frozen(self, environment: str, at: datetime) -> bool:
        return any(f.applies(environment, at) for f in self.freezes)
