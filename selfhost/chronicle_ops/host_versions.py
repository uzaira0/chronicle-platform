"""Minimum container-runtime and kernel versions, set by the 2026 CVE sweep.

Every version check here is a warning on every path (setup, check, up, update, doctor) and never
makes a command fail: an operator must always be able to run `./chronicle update`. The architecture
check (architecture_assessment) also only warns on up and update; a fresh setup refuses and check
fails only when the daemon cannot run the linux/amd64 release images at all, not under emulation. Versions come from the
Docker daemon (`docker version`, `docker info`), so a Docker Desktop trial reports its VM's
kernel, the one containers run on. Distribution kernels carry fixes as backports under older
version numbers, so the kernel warning says to confirm with the vendor.
"""
import json
import re
import subprocess

from .common import run

# A version passes when it is at or above the fixed release of its own major.minor series, or is
# on a newer series than every fixed release. Older series, and series between fixed ones that
# received no fix, fail.
ENGINE_FIXED = ((29, 8, 2),)
CONTAINERD_FIXED = ((2, 2, 10), (2, 3, 7), (2, 4, 2))
RUNC_FIXED = ((1, 3, 6), (1, 4, 3))
# CVE-2026-31431 (fixed in 5.10.254, 5.15.204, 6.1.170, 6.6.137, 6.12.85, 6.18.22, 6.19.12) and
# CVE-2026-53362 (IPv6, introduced in 6.0; fixed in 6.1.177, 6.6.144, 6.12.95, 6.18.38, 7.1.3).
KERNEL_FIXED = ((5, 10, 254), (5, 15, 204), (6, 1, 177), (6, 6, 144), (6, 12, 95), (6, 18, 38), (7, 1, 3))
KERNEL_CVES = "CVE-2026-31431 and CVE-2026-53362"


def parse(text):
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(part) for part in match.groups()) if match else None


def meets(version, fixed):
    for release in fixed:
        if release[:2] == version[:2]:
            return version >= release
    return version[:2] > max(release[:2] for release in fixed)


def releases(fixed):
    names = [".".join(map(str, release)) for release in fixed]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " or " + names[-1]


# Advisories fixed at or below each minimum (GitHub advisories and NVD, 2026 sweep).
RUNTIME = (("Docker Engine", "engine", ENGINE_FIXED, "",
            "CVE-2026-92543 (registry TLS bypass) and CVE-2026-34040 (AuthZ plugin bypass)"),
           ("containerd", "containerd", CONTAINERD_FIXED, "; the 1.7 line has no fix",
            "CVE-2026-95837 (CRI checkpoint restore), CVE-2026-53493 and CVE-2026-95838 (image-pull and unpack DoS)"),
           ("runc", "runc", RUNC_FIXED, "", "CVE-2026-41579 (/dev symlink in a malicious image)"))


def runtime_rows(server):
    """(status, message) rows for the Engine, containerd and runc reported in `docker version`'s Server."""
    components = {str(item.get("Name", "")).lower(): item.get("Version") for item in server.get("Components") or []}
    rows = []
    for name, component, fixed, note, cves in RUNTIME:
        raw = (server.get("Version") or components.get(component)) if component == "engine" else components.get(component)
        version = parse(raw)
        if version is None:
            rows.append(("warn", f"could not read the {name} version from docker version; Chronicle expects {name} "
                                 f"{releases(fixed)} or newer, which fix {cves}"))
        elif meets(version, fixed):
            rows.append(("ok", f"{name} {raw}"))
        else:
            rows.append(("warn", f"{name} {raw} is older than {releases(fixed)}{note}: it lacks the fixes for "
                                 f"{cves}. Upgrade Docker from Docker's own repository with your package manager "
                                 "(docker-ce, containerd.io; see the README Requirements). Chronicle keeps running meanwhile"))
    return rows


def kernel_row(raw):
    version = parse(raw)
    if version is not None and meets(version, KERNEL_FIXED):
        return ("ok", f"kernel {raw}")
    return ("warn", f"kernel {raw or 'version unknown'} is not an upstream release fixing {KERNEL_CVES} "
                    f"({releases(KERNEL_FIXED[2:])}; or 5.10.254 / 5.15.204), which CISA lists as exploited and "
                    "which a container under Docker's default seccomp profile can reach. A distribution kernel "
                    "may carry both fixes as backports: confirm with your vendor's advisories, or install a fixed kernel")


def collect(runner=run):
    """(status, message) rows; status is "ok" or "warn". runner runs one docker command."""
    try:
        result = runner(["docker", "version", "--format", "{{json .Server}}"], capture=True, timeout=30)
        server = json.loads(result.stdout) if result.returncode == 0 and result.stdout else None
    except (OSError, ValueError, subprocess.SubprocessError):
        server = None
    rows = runtime_rows(server if isinstance(server, dict) else {})
    try:
        result = runner(["docker", "info", "--format", "{{.KernelVersion}}"], capture=True, timeout=30)
        kernel = (result.stdout or "").strip() if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        kernel = ""
    rows.append(kernel_row(kernel))
    return rows


# The release images are built for linux/amd64 only (scripts/publish-images.sh release_platform,
# toolchain-manifest.yaml). Docker reports its daemon's architecture with uname -m names.
AMD64 = ("x86_64", "amd64")
OTHER_ARCHITECTURES = ("aarch64", "arm64", "armv7l", "armv6l", "arm", "i386", "i686", "ppc64le", "s390x",
                       "riscv64", "mips64", "loongarch64")


def architecture_problem(arch):
    """What to tell the operator when the Docker daemon runs on a known non-amd64 architecture;
    None on amd64 or when the answer is not an architecture name (unknown is not a problem)."""
    arch = (arch or "").strip()
    if arch in AMD64 or arch not in OTHER_ARCHITECTURES:
        return None
    return (f"this Docker daemon runs on {arch}, but Chronicle's release images are published for "
            "linux/amd64 (x86_64) only, so they cannot be pulled or run here. Use an amd64 host "
            "(README Requirements)")


def daemon_architecture(runner=run):
    try:
        result = runner(["docker", "info", "--format", "{{.Architecture}}"], capture=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ""
    return (result.stdout or "").strip() if result.returncode == 0 else ""


# The amd64 probe: the bundled Caddy image (small, Alpine, already pulled by setup for password
# hashing) runs /bin/true with no network, no capabilities and a read-only root.
PROBE_IMAGE_VARIABLE = "CADDY_IMAGE"
PROBE_ARGUMENTS = ("--platform", "linux/amd64", "--network", "none", "--read-only", "--cap-drop", "ALL",
                   "--entrypoint", "/bin/true")


def probe_image():
    """The digest-pinned bundled image to probe with: the environment (the launcher exports .env),
    then .env, then the release's .env.example; None in a source checkout (placeholders)."""
    import os
    from pathlib import Path

    from .envfile import read_env, value
    candidates = [os.environ.get(PROBE_IMAGE_VARIABLE, "")]
    for name in (".env", ".env.example"):
        try:
            candidates.append(value(read_env(Path.cwd() / name), PROBE_IMAGE_VARIABLE))
        except (OSError, ValueError):
            continue
    return next((image for image in candidates if "@sha256:" in image), None)


def architecture_assessment(runner=run):
    """(level, message): (None, None) on amd64 or an unknown answer; ("warn", ...) when another
    architecture runs the amd64 images under emulation, or when that could not be checked;
    ("refuse", ...) only when the daemon cannot execute amd64 code at all (exec format error).

    Docker Desktop and OrbStack on Apple silicon, and Linux hosts with amd64 binfmt emulation, run
    the images, so a fresh setup there must not be refused; the probe runs the bundled image to tell."""
    arch = daemon_architecture(runner)
    problem = architecture_problem(arch)
    if not problem:
        return None, None
    image = probe_image()
    reason = "no digest-pinned release image to test with"
    if image:
        from .common import transfer_timeout
        try:
            result = runner(["docker", "run", "--rm", "--pull", "missing", *PROBE_ARGUMENTS, image], capture=True,
                            stderr=subprocess.PIPE, timeout=transfer_timeout())
        except (OSError, subprocess.SubprocessError) as error:
            result, reason = None, str(error)
        if result is not None and result.returncode == 0:
            return "warn", (f"this Docker daemon runs on {arch} and runs Chronicle's linux/amd64 images under "
                            "emulation (the bundled Caddy image ran): performance is emulated and slower. Fine for a "
                            "trial; use an amd64 host for production (README Requirements)")
        if result is not None:
            output = " ".join(((result.stdout or "") + " " + (result.stderr or "")).split())
            if "exec format error" in output.lower():
                return "refuse", (f"this Docker daemon runs on {arch} and cannot run linux/amd64 images (the bundled "
                                  "Caddy image failed: exec format error); Chronicle's release images are published for "
                                  "linux/amd64 only. Use an amd64 host, or enable amd64 emulation (binfmt/QEMU) for "
                                  "this daemon (README Requirements)")
            reason = output[:200] or f"docker run exited {result.returncode}"
    return "warn", (f"{problem}; could not check whether it runs them under emulation ({reason}). If containers "
                    "fail with exec format error, use an amd64 host")


def warn_architecture(runner=run):
    """Warn on a non-amd64 daemon (update, which must never be refused for it). No probe: the
    deployment being updated already runs, so the daemon runs amd64 images, under emulation."""
    from .common import warn
    arch = daemon_architecture(runner)
    if architecture_problem(arch):
        warn(f"this Docker daemon runs on {arch}; Chronicle's linux/amd64 images run here under emulation, "
             "so performance is emulated and slower. Use an amd64 host for production (README Requirements)")


def architecture_check():
    """`ops host-architecture`: print the assessment's message. Exit 1 when amd64 images cannot run
    (setup refuses, check fails, up warns), 2 for a warning, 0 when there is nothing to say."""
    level, message = architecture_assessment()
    if message:
        print(message)
    return {"refuse": 1, "warn": 2}.get(level, 0)


def warn_outdated(runner=run):
    """Print each outdated or unreadable version as a warning (update)."""
    from .common import warn
    for status, message in collect(runner):
        if status != "ok":
            warn(message)


def check():
    for status, message in collect():
        print(status + "\t" + message)
    return 0
