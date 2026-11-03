"""Host tools used by operator regression fixtures."""

import shutil
import subprocess


def modern_bash() -> str:
    bash = shutil.which("bash")
    assert bash, "bash is not on PATH"
    version = subprocess.run([bash, "-c", 'printf "%s.%s" "${BASH_VERSINFO[0]}" "${BASH_VERSINFO[1]}"'],
                             capture_output=True, text=True, check=True, timeout=10).stdout
    assert tuple(map(int, version.split("."))) >= (4, 4), f"{bash} is bash {version}; put bash 4.4 or later first on PATH"
    return bash
