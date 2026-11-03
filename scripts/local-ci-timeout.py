"""Bound and redact local CI command output."""

import argparse
from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

redact_pattern = re.compile(r"(?i)(NVD_API_KEY|nvdApiKey|apiKey)(\s*[:=]\s*)([^ \t\r\n]+)")

def redact(text: str) -> str:
    return redact_pattern.sub(r"\1\2[redacted]", text)

def write(stream, log, text: str) -> None:
    redacted = redact(text)
    stream.write(redacted)
    stream.flush()
    log.write(redacted)
    log.flush()

def signal_group(process, selected_signal):
    try:
        os.killpg(process.pid, selected_signal)
    except ProcessLookupError:
        return False
    return True


def unregister(selector, stream):
    if stream in selector.get_map():
        selector.unregister(stream)


@dataclass(frozen=True)
class TimedCommand:
    seconds: float
    log_path: Path
    argv: tuple[str, ...]


def parse_request(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('seconds', type=float)
    parser.add_argument('log_path', type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    options = parser.parse_args(argv)
    if not math.isfinite(options.seconds) or options.seconds < 0:
        parser.error('timeout must be a finite nonnegative number')
    if options.seconds and not options.command:
        parser.error('a command is required for a nonzero timeout')
    return TimedCommand(seconds=options.seconds, log_path=options.log_path.resolve(), argv=tuple(options.command))


def run_command(request: TimedCommand, log):
    proc = subprocess.Popen(
        request.argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, sys.stdout)
    selector.register(proc.stderr, selectors.EVENT_READ, sys.stderr)
    deadline = time.monotonic() + request.seconds

    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0 and proc.poll() is None:
            msg = f"[local-ci] command timed out after {int(request.seconds)}s: {' '.join(request.argv)}\n"
            write(sys.stderr, log, msg)
            signal_group(proc, signal.SIGTERM)
            kill_deadline = time.monotonic() + 15
            while time.monotonic() < kill_deadline:
                if proc.poll() is not None:
                    break
                time.sleep(0.5)
            if proc.poll() is None:
                signal_group(proc, signal.SIGKILL)
            proc.wait()
            return 124

        events = selector.select(timeout=max(0.1, min(1.0, remaining)))
        if not events:
            if proc.poll() is not None:
                for fileobj, stream in ((proc.stdout, sys.stdout), (proc.stderr, sys.stderr)):
                    rest = fileobj.read()
                    if rest:
                        write(stream, log, rest)
                    unregister(selector, fileobj)
            continue

        for key, _ in events:
            line = key.fileobj.readline()
            if line:
                write(key.data, log, line)
            else:
                unregister(selector, key.fileobj)

    proc.wait()
    if proc.returncode != 0:
        return proc.returncode
    return 0


def main(argv=None):
    request = parse_request(argv)
    with request.log_path.open('a', encoding='utf-8', errors='replace') as log:
        if request.seconds == 0:
            for line in sys.stdin:
                write(sys.stdout, log, line)
            return 0
        return run_command(request, log)


if __name__ == '__main__':
    sys.exit(main())
