from pathlib import Path

VERSION = "6.0.8"
USER = "knot-resolver"
GROUP = "knot-resolver"

# dirs paths
RUN_DIR = Path("/run/knot-resolver")
ETC_DIR = Path("/etc/knot-resolver")
SBIN_DIR = Path("/usr/bin")

# files paths
CONFIG_FILE = ETC_DIR / "config.yaml"
API_SOCK_FILE = RUN_DIR / "kres-api.sock"

# environmental variables
CONFIG_FILE_ENV_VAR = "KRES_CONFIG_FILE"
API_SOCK_FILE_ENV_VAR = "KRES_API_SOCK_FILE"

# executables paths
KRESD_EXECUTABLE = SBIN_DIR / "kresd"
KRES_CACHE_GC_EXECUTABLE = SBIN_DIR / "kres-cache-gc"
