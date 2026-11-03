"""Schedules exactly as the backup sidecar's go-cron v0.0.11 reads them.

go-cron (gocron/go-cron.go:100-104) parses its -s value with robfig/cron v3.0.1 configured as
SecondOptional | Minute | Hour | Dom | Month | Dow | Descriptor, and ignores the parse error
(go-cron.go:109): a value robfig refuses, or one that never runs, leaves the sidecar idle. parse()
mirrors robfig's parser.go and longest_gap() its spec.go Next, so the overdue window can never be
shorter than a gap go-cron really leaves between dumps.
"""

from bisect import bisect_right
import datetime
import re
from typing import FrozenSet, NamedTuple, Optional
import zoneinfo

_MONTHS = {name: number for number, name in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), start=1)}
_WEEKDAYS = {name: number for number, name in enumerate(("sun", "mon", "tue", "wed", "thu", "fri", "sat"))}
# second, minute, hour, day of month, month, day of week (robfig spec.go:22-48)
_BOUNDS = ((0, 59, None), (0, 59, None), (0, 23, None), (1, 31, None), (1, 12, _MONTHS), (0, 6, _WEEKDAYS))
# robfig parser.go:366-421, written as the six-field specs they expand to.
_DESCRIPTORS = {"@yearly": "0 0 0 1 1 *", "@annually": "0 0 0 1 1 *", "@monthly": "0 0 0 1 * *",
                "@weekly": "0 0 0 * * 0", "@daily": "0 0 0 * * *", "@midnight": "0 0 0 * * *",
                "@hourly": "0 0 * * * *"}
# Go time.ParseDuration units, in nanoseconds.
_UNITS = {"ns": 1, "us": 10**3, "µs": 10**3, "μs": 10**3, "ms": 10**6, "s": 10**9,
          "m": 60 * 10**9, "h": 3600 * 10**9}
_INT64_LIMIT = 1 << 63
# 28 years from this January covers every leap-year and weekday alignment of the Gregorian
# calendar until the 2100 non-leap year falls inside it.
_WINDOW_YEARS = 28


class Spec(NamedTuple):
    second: FrozenSet[int]
    minute: FrozenSet[int]
    hour: FrozenSet[int]
    dom: FrozenSet[int]
    month: FrozenSet[int]
    dow: FrozenSet[int]
    dom_star: bool
    dow_star: bool
    # The TZ= zone. None is go-cron's Local, which is UTC in the sidecar: the image sets no TZ
    # and has no /etc/localtime.
    zone: Optional[datetime.tzinfo] = None

    def runs_on(self, day):
        """robfig dayMatches (spec.go:179-188): a * on either day field means both must match."""
        if day.month not in self.month:
            return False
        dom, dow = day.day in self.dom, (day.weekday() + 1) % 7 in self.dow
        return dom and dow if self.dom_star or self.dow_star else dom or dow


def _leading(pattern, text):
    match = re.match(pattern, text)
    return match[0] if match else ""


def _number(text, names):
    """robfig parseIntOrName: a case-insensitive name, else strconv.Atoi, never negative."""
    if names and text.lower() in names:
        return names[text.lower()]
    if not re.fullmatch(r"[+-]?[0-9]+", text) or int(text) >= _INT64_LIMIT:
        raise ValueError(f"'{text}' is not a number")
    if int(text) < 0:
        raise ValueError(f"negative number {text} is not allowed")
    return int(text)


def _field(text, low, high, names):
    """robfig getField/getRange (parser.go:236-318): returns the values and whether a * was used."""
    values, star = set(), False
    for expr in (part for part in text.split(",") if part):
        range_and_step = expr.split("/")
        low_and_high = range_and_step[0].split("-")
        extra = low_and_high[0] in ("*", "?")
        if extra:
            start, end = low, high
        elif len(low_and_high) > 2:
            raise ValueError(f"too many hyphens: {expr}")
        else:
            start = _number(low_and_high[0], names)
            end = _number(low_and_high[-1], names)
        step = 1
        if len(range_and_step) > 2:
            raise ValueError(f"too many slashes: {expr}")
        if len(range_and_step) == 2:
            step = _number(range_and_step[1], None)
            if len(low_and_high) == 1:
                end = high
            extra = extra and step <= 1
        if start < low or end > high or start > end:
            raise ValueError(f"{expr} is outside {low}-{high}")
        if step == 0:
            raise ValueError(f"step of {expr} must be positive")
        values.update(range(start, end + 1, step))
        star = star or extra
    return frozenset(values), star


def _zone(name):
    """Go time.LoadLocation: None for UTC and Local (UTC in the sidecar). Without a zone database
    here the name is left to go-cron and gaps are measured on its wall clock."""
    if name in ("", "UTC", "Local"):
        return None
    try:
        return zoneinfo.ZoneInfo(name)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        if zoneinfo.available_timezones():
            raise ValueError(f"unknown time zone {name}") from None
        return None


def parse_duration(text):
    """Go time.ParseDuration, in nanoseconds; raises ValueError where Go returns an error."""
    rest, negative, total = text, False, 0
    if rest[:1] in ("+", "-"):
        negative, rest = rest[0] == "-", rest[1:]
    if rest == "0":
        return 0
    if not rest:
        raise ValueError(f"invalid duration '{text}'")
    while rest:
        whole = _leading(r"[0-9]*", rest)
        rest = rest[len(whole):]
        value, fraction, scale, fraction_digits = int(whole or 0), 0, 1.0, ""
        if value > _INT64_LIMIT:
            raise ValueError(f"invalid duration '{text}'")
        if rest.startswith("."):
            fraction_digits = _leading(r"[0-9]*", rest[1:])
            rest = rest[1 + len(fraction_digits):]
            overflow = False
            for digit in fraction_digits:  # Go leadingFraction: extra digits are read and dropped
                if overflow or fraction > (_INT64_LIMIT - 1) // 10 or fraction * 10 + int(digit) > _INT64_LIMIT:
                    overflow = True
                    continue
                fraction, scale = fraction * 10 + int(digit), scale * 10
        if not whole and not fraction_digits:
            raise ValueError(f"invalid duration '{text}'")
        unit = _leading(r"[^0-9.]*", rest)
        rest = rest[len(unit):]
        if unit not in _UNITS:
            raise ValueError(f"unknown or missing unit in duration '{text}'")
        if value > _INT64_LIMIT // _UNITS[unit]:
            raise ValueError(f"invalid duration '{text}'")
        value *= _UNITS[unit]
        if fraction:
            value += int(float(fraction) * (float(_UNITS[unit]) / scale))
        total += value
        if value > _INT64_LIMIT or total > _INT64_LIMIT:
            raise ValueError(f"invalid duration '{text}'")
    if not negative and total > _INT64_LIMIT - 1:
        raise ValueError(f"invalid duration '{text}'")
    return -total if negative else total


def parse(text):
    """robfig Parser.Parse (parser.go:88-153): a Spec, or the whole seconds of an @every delay."""
    zone = None
    if text.startswith(("TZ=", "CRON_TZ=")):
        if " " not in text:
            raise ValueError("a time zone with no schedule after it")
        space = text.index(" ")
        zone = _zone(text[text.index("=") + 1:space])
        text = text[space:].strip()
    if text.startswith("@every "):
        # robfig Every (constantdelay.go:14-21): under one second runs every second, whole seconds only.
        return max(parse_duration(text[len("@every "):]), 10**9) // 10**9
    if text.startswith("@"):
        if text not in _DESCRIPTORS:
            raise ValueError(f"unrecognized descriptor {text}")
        text = _DESCRIPTORS[text]
    fields = text.split()
    if len(fields) == 5:
        fields.insert(0, "0")
    if len(fields) != 6:
        raise ValueError(f"expected 5 or 6 fields, found {len(fields)}")
    (second, _), (minute, _), (hour, _), (dom, dom_star), (month, _), (dow, dow_star) = (
        _field(field, *bounds) for field, bounds in zip(fields, _BOUNDS))
    return Spec(second, minute, hour, dom, month, dow, dom_star, dow_star, zone)


def _offset(zone, instant):
    return int(datetime.datetime.fromtimestamp(instant, zone).utcoffset().total_seconds())


def _wall_changes(zone, first, last):
    """Each UTC-offset change between two instants as (lo, hi, before, after): the wall-clock
    seconds [lo, hi) that the change skips (after > before) or repeats (after < before). Found by
    sampling once a day and bisecting to the second; no zone changes its offset twice in a day."""
    changes, previous = [], _offset(zone, first)
    for sample in range(first + 86400, last + 86400, 86400):
        current = _offset(zone, sample)
        if current != previous:
            low, high = sample - 86400, sample
            while high - low > 1:
                middle = (low + high) // 2
                low, high = (middle, high) if _offset(zone, middle) == previous else (low, middle)
            changes.append((high + min(previous, current), high + max(previous, current), previous, current))
            previous = current
    return changes


def longest_gap(spec, start, days) -> Optional[int]:
    """Longest wait in seconds between consecutive runs on the `days` local dates from `start`, or
    None when fewer than two runs fall in that window.

    Runs are wall-clock times in spec.zone. robfig's Next (spec.go:58-175) steps hours and minutes
    by elapsed time, so a wall time that a daylight-saving change skips never runs (00:00 on a
    day that starts at 01:00 included) and one that the change repeats runs twice. Gaps are taken
    between the resulting UTC instants."""
    times = [hour * 3600 + minute * 60 + second for hour in sorted(spec.hour)
             for minute in sorted(spec.minute) for second in sorted(spec.second)]
    if not times:
        return None
    epoch, first = datetime.date(1970, 1, 1).toordinal(), start.toordinal()
    changes, base = [], 0
    if spec.zone is not None:
        window = ((first - epoch) * 86400 - 86400, (first + days - epoch) * 86400 + 86400)
        changes, base = _wall_changes(spec.zone, *window), _offset(spec.zone, window[0])
    starts = [change[0] for change in changes]

    def governing(wall):
        index = bisect_right(starts, wall) - 1
        return changes[index] if index >= 0 else None

    def instants(wall):
        change = governing(wall)
        if change is None:
            return [wall - base]
        lo, hi, before, after = change
        if wall >= hi:
            return [wall - after]
        return [] if after > before else [wall - before, wall - after]

    inner = max((later - earlier for earlier, later in zip(times, times[1:])), default=0)
    gaps, previous_last = [], None
    for ordinal in range(first, first + days):
        if not spec.runs_on(datetime.date.fromordinal(ordinal)):
            continue
        day = (ordinal - epoch) * 86400
        change = governing(day + times[0])
        if change is governing(day + times[-1]) and (change is None or day + times[0] >= change[1]):
            offset = base if change is None else change[3]
            runs = [day + times[0] - offset, day + times[-1] - offset]
            if len(times) > 1:
                gaps.append(inner)
        else:
            runs = sorted(instant for time in times for instant in instants(day + time))
            gaps += [later - earlier for earlier, later in zip(runs, runs[1:])]
        if not runs:
            continue
        if previous_last is not None:
            gaps.append(runs[0] - previous_last)
        previous_last = runs[-1]
    return max(gaps, default=None)


def longest_gap_seconds(text):
    """Longest wait between two runs of `text` as go-cron schedules it; ValueError when go-cron
    would refuse it or never run it."""
    schedule = parse(text)
    if isinstance(schedule, int):
        return schedule
    january = datetime.date(datetime.date.today().year, 1, 1)
    gap = longest_gap(schedule, january, datetime.date(january.year + _WINDOW_YEARS, 1, 1).toordinal() - january.toordinal())
    if gap is None:
        raise ValueError("never runs, so go-cron would take no backups")
    return gap
