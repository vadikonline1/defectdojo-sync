"""Shared helpers for openvas_sync + wazuh_sync (all-in-one image)."""
import logging
import os
import warnings
from pathlib import Path

import requests
import urllib3

# Certificatul e skip-uit peste tot (WAZUH/OPENSEARCH/DEFECTDOJO au verify=false
# in .env) -> suprimam si warning-urile zgomotoase, ca sa ramana loguri curate.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings(
    "ignore",
    message=".*verify_certs=False.*",
    category=UserWarning,
    module="opensearchpy.*",
)
warnings.filterwarnings(
    "ignore",
    category=UserWarning,
    module="opensearchpy.*",
)
# opensearch-py logheaza fiecare request pe INFO -> le urcam la WARNING
logging.getLogger("opensearch").setLevel(logging.WARNING)
logging.getLogger("elastic_transport").setLevel(logging.WARNING)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(message)s",
)

DEFECTDOJO_URL = os.getenv(
    "DEFECTDOJO_URL", "http://host.docker.internal:8080"
).rstrip("/")
DEFECTDOJO_API_TOKEN = os.getenv("DEFECTDOJO_API_TOKEN", "")
DEFECTDOJO_VERIFY_TLS = os.getenv("DEFECTDOJO_VERIFY_TLS", "false").lower() == "true"
DEFECTDOJO_PRODUCT_TYPE = os.getenv("DEFECTDOJO_PRODUCT_TYPE", "Security Scanning")
DEFECTDOJO_PRODUCT_DEFAULT = os.getenv("DEFECTDOJO_PRODUCT", "Greenbone")
DEFECTDOJO_ENGAGEMENT_DEFAULT = os.getenv("DEFECTDOJO_ENGAGEMENT", "Greenbone Automated Scans")

SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", "3600"))


def get_logger(name):
    return logging.getLogger(name)


def dd_headers():
    if not DEFECTDOJO_API_TOKEN:
        raise RuntimeError("DEFECTDOJO_API_TOKEN lipsa in .env")
    return {
        "Authorization": f"Token {DEFECTDOJO_API_TOKEN}",
        "Accept": "application/json",
    }


def dd_check(log):
    r = requests.get(
        f"{DEFECTDOJO_URL}/api/v2/",
        headers=dd_headers(),
        verify=DEFECTDOJO_VERIFY_TLS,
        timeout=30,
    )
    if r.status_code >= 400:
        raise RuntimeError(
            f"DefectDojo API HTTP {r.status_code}: {r.text[:300]}"
        )
    log.info("DefectDojo OK: HTTP %s", r.status_code)


def dd_post_scan(log, endpoint, data, file_path, timeout=600):
    """POST a report file to import-scan / reimport-scan. Returns response."""
    url = f"{DEFECTDOJO_URL}/api/v2/{endpoint}/"
    with open(file_path, "rb") as f:
        r = requests.post(
            url,
            headers=dd_headers(),
            data=data,
            files={"file": (Path(file_path).name, f, "application/octet-stream")},
            verify=DEFECTDOJO_VERIFY_TLS,
            timeout=timeout,
        )
    if r.status_code >= 400:
        raise RuntimeError(
            f"DefectDojo {endpoint} HTTP {r.status_code}: {r.text[:2000]}"
        )
    log.info("DefectDojo %s OK: HTTP %s", endpoint, r.status_code)
    return r


def init_storage(log, dirs):
    """Init: creeaza directoarele de rapoarte/state (wazuh-*, openvas-*)."""
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
    log.info("Storage init OK: %s", ", ".join(str(d) for d in dirs))
