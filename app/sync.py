import hashlib
import logging
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from xml.etree import ElementTree as ET

import requests
from apscheduler.schedulers.blocking import BlockingScheduler
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("greenbone-defectdojo-sync")

GVM_SOCKET = os.getenv("GVM_SOCKET", "/run/gvmd/gvmd.sock")
GVM_USERNAME = os.getenv("GVM_USERNAME", "admin")
GVM_PASSWORD = os.getenv("GVM_PASSWORD", "")

DEFECTDOJO_URL = os.getenv(
    "DEFECTDOJO_URL", "http://host.docker.internal:8080"
).rstrip("/")
DEFECTDOJO_API_TOKEN = os.getenv("DEFECTDOJO_API_TOKEN", "")
DEFECTDOJO_VERIFY_TLS = os.getenv("DEFECTDOJO_VERIFY_TLS", "false").lower() == "true"

DEFECTDOJO_PRODUCT = os.getenv("DEFECTDOJO_PRODUCT", "Greenbone")
DEFECTDOJO_PRODUCT_TYPE = os.getenv("DEFECTDOJO_PRODUCT_TYPE", "Security Scanning")
DEFECTDOJO_ENGAGEMENT = os.getenv("DEFECTDOJO_ENGAGEMENT", "Greenbone Automated Scans")
# NOTE: "OpenVAS Parser v2" currently crashes in DefectDojo (cleanup_openvas_text(None)
# when <solution/> is empty). Use v1 "OpenVAS Parser" which handles wrapper XML correctly.
DEFECTDOJO_SCAN_TYPE = os.getenv("DEFECTDOJO_SCAN_TYPE", "OpenVAS Parser")

SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", "3600"))
REPORT_DIRECTORY = Path(os.getenv("REPORT_DIRECTORY", "/data/reports"))
STATE_FILE = REPORT_DIRECTORY / "sync-state.txt"

IMPORT_ONLY_FINISHED = os.getenv("IMPORT_ONLY_FINISHED", "true").lower() == "true"


@contextmanager
def gmp_session():
    """Yield an authenticated GMP session.

    In python-gvm >= 25, ``GMP`` from ``gvm.protocols.gmp`` is a dispatcher
    that must be used as a context manager. On __enter__ it negotiates the
    remote GMP version (e.g. GMPv227) and connects the socket.
    """
    if not GVM_USERNAME or not GVM_PASSWORD:
        raise RuntimeError("GVM_USERNAME or GVM_PASSWORD is empty")
    connection = UnixSocketConnection(path=GVM_SOCKET)
    transform = EtreeCheckCommandTransform()
    log.info("Connecting to Greenbone through %s", GVM_SOCKET)
    with GMP(connection=connection, transform=transform) as gmp:
        log.info("Negotiated GMP class: %s", type(gmp).__name__)
        gmp.authenticate(GVM_USERNAME, GVM_PASSWORD)
        log.info("Greenbone authentication successful")
        yield gmp
    log.info("Disconnected from Greenbone")


def get_report_formats(gmp):
    response = gmp.get_report_formats()
    formats = response.findall(".//report_format")

    for report_format in formats:
        name = report_format.findtext("name", "").strip()
        if name.lower() == "xml":
            return report_format.get("id"), name

    for report_format in formats:
        name = report_format.findtext("name", "").strip()
        if "xml" in name.lower():
            return report_format.get("id"), name

    for report_format in formats:
        extension = report_format.findtext("extension", "").strip()
        if extension.lower() == "xml":
            return report_format.get("id"), report_format.findtext("name", "").strip()

    raise RuntimeError("Could not find an XML report format in Greenbone")


def get_tasks(gmp):
    response = gmp.get_tasks(details=True)
    tasks = []

    for task in response.findall(".//task"):
        task_id = task.get("id")
        name = task.findtext("name", "").strip()
        status = task.findtext("status", "").strip()
        last_report = task.find(".//last_report/report")
        report_id = last_report.get("id") if last_report is not None else None

        tasks.append({
            "id": task_id,
            "name": name,
            "status": status,
            "report_id": report_id,
        })

    return tasks


def get_report_xml(gmp, report_id, report_format_id):
    response = gmp.get_report(
        report_id=report_id,
        report_format_id=report_format_id,
        ignore_pagination=True,
        details=True,
    )

    wrapper_report = response.find("report")
    if wrapper_report is None:
        raise RuntimeError(
            f"Greenbone response does not contain wrapper report for {report_id}"
        )

    # DefectDojo "OpenVAS Parser v2" expects the OUTER <report> wrapper:
    #   <report format_id="a994b278-...">
    #     <report id="...">
    #       <results>...
    # i.e. root.find("report").find("results") must exist.
    # Serializing only the inner <report> breaks the parser with
    # "'NoneType' object has no attribute 'find'".
    report_payload = wrapper_report.find("report")
    if report_payload is None:
        raise RuntimeError(
            f"Greenbone response does not contain nested report payload for {report_id}"
        )
    if report_payload.find("results") is None:
        raise RuntimeError(
            f"Nested report payload for {report_id} has no <results>"
        )

    xml_bytes = ET.tostring(
        wrapper_report,
        encoding="utf-8",
        xml_declaration=True,
    )

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise RuntimeError(
            f"Extracted OpenVAS report is not valid XML: {exc}"
        ) from exc

    if root.tag != "report":
        raise RuntimeError(f"Unexpected OpenVAS XML root element: {root.tag!r}")
    # Validate DefectDojo v2 contract: root.find("report").find("results")
    nested = root.find("report")
    if nested is None or nested.find("results") is None:
        raise RuntimeError(
            f"Extracted XML for {report_id} does not match DefectDojo "
            "OpenVAS Parser v2 structure (report/report/results)"
        )

    log.info("Extracted OpenVAS report wrapper: id=%s", report_id)
    log.info("OpenVAS XML validated successfully: %d bytes", len(xml_bytes))
    return xml_bytes


def load_state():
    if not STATE_FILE.exists():
        return set()
    return {
        line.strip()
        for line in STATE_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def save_state(report_id):
    REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    with STATE_FILE.open("a", encoding="utf-8") as f:
        f.write(report_id + "\n")


def save_report(report_id, xml_bytes):
    REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIRECTORY / f"{report_id}.xml"
    path.write_bytes(xml_bytes)
    log.info("Saved OpenVAS XML: %s", path)
    return path


def defectdojo_headers():
    if not DEFECTDOJO_API_TOKEN:
        raise RuntimeError("DEFECTDOJO_API_TOKEN is empty")
    return {
        "Authorization": f"Token {DEFECTDOJO_API_TOKEN}",
        "Accept": "application/json",
    }


def check_defectdojo():
    url = f"{DEFECTDOJO_URL}/api/v2/"
    response = requests.get(
        url,
        headers=defectdojo_headers(),
        verify=DEFECTDOJO_VERIFY_TLS,
        timeout=30,
    )

    if response.status_code >= 400:
        raise RuntimeError(
            f"DefectDojo API check failed: HTTP {response.status_code}: "
            f"{response.text[:500]}"
        )

    log.info("DefectDojo API reachable: HTTP %s", response.status_code)


def import_into_defectdojo(xml_path, task_name, report_id):
    url = f"{DEFECTDOJO_URL}/api/v2/reimport-scan/"

    data = {
        "scan_type": DEFECTDOJO_SCAN_TYPE,
        "product_name": DEFECTDOJO_PRODUCT,
        "product_type_name": DEFECTDOJO_PRODUCT_TYPE,
        "engagement_name": DEFECTDOJO_ENGAGEMENT,
        "test_title": f"Greenbone - {task_name}",
        "auto_create_context": "true",
        "active": "true",
        "verified": "false",
        "minimum_severity": "Info",
        "tags": f"greenbone,task:{task_name},report:{report_id}",
    }

    with xml_path.open("rb") as f:
        response = requests.post(
            url,
            headers=defectdojo_headers(),
            data=data,
            files={"file": (xml_path.name, f, "application/xml")},
            verify=DEFECTDOJO_VERIFY_TLS,
            timeout=300,
        )

    if response.status_code >= 400:
        raise RuntimeError(
            f"DefectDojo import failed: HTTP {response.status_code}: "
            f"{response.text[:2000]}"
        )

    log.info("DefectDojo import successful: HTTP %s", response.status_code)
    return response


def sync():
    log.info("========== Greenbone -> DefectDojo sync started ==========")

    check_defectdojo()

    with gmp_session() as gmp:
        version = gmp.get_version()
        # get_version returns <get_version_response><version>22.7</version>...
        gmp_version = version.findtext("version") if hasattr(version, "findtext") else version.text
        log.info("Greenbone GMP version: %s (negotiated %s)", gmp_version, type(gmp).__name__)

        report_format_id, report_format_name = get_report_formats(gmp)
        log.info(
            "Using Greenbone report format: %s (%s)",
            report_format_name,
            report_format_id,
        )

        tasks = get_tasks(gmp)
        log.info("Found %d Greenbone tasks", len(tasks))

        state = load_state()
        imported = 0
        skipped = 0

        for task in tasks:
            task_id = task["id"]
            task_name = task["name"]
            status = task["status"]
            report_id = task["report_id"]

            log.info(
                "Task: id=%s name=%r status=%s report_id=%s",
                task_id, task_name, status, report_id,
            )

            if IMPORT_ONLY_FINISHED and status.lower() not in {"done", "stopped"}:
                log.info("Skipping unfinished task %s with status %s", task_id, status)
                skipped += 1
                continue

            if not report_id:
                log.info("Skipping task %s: no last report", task_id)
                skipped += 1
                continue

            if report_id in state:
                log.info("Skipping report %s: already imported", report_id)
                skipped += 1
                continue

            try:
                xml_bytes = get_report_xml(gmp, report_id, report_format_id)
                checksum = hashlib.sha256(xml_bytes).hexdigest()
                log.info("Report SHA256: %s", checksum)

                xml_path = save_report(report_id, xml_bytes)
                ET.parse(str(xml_path))
                log.info("Report XML validation: OK")

                import_into_defectdojo(xml_path, task_name, report_id)

                save_state(report_id)
                state.add(report_id)
                imported += 1

            except Exception:
                log.exception(
                    "Failed to process task %s / report %s",
                    task_id, report_id,
                )

        log.info(
            "========== Sync finished: imported=%d skipped=%d ==========",
            imported, skipped,
        )


def list_tasks():
    check_defectdojo()
    with gmp_session() as gmp:
        tasks = get_tasks(gmp)

        print()
        print("Greenbone tasks:")
        print("-" * 100)

        for task in tasks:
            print(
                f"{task['id']} | {task['status']:<10} | "
                f"{task['name']} | report={task['report_id']}"
            )

        print("-" * 100)


def main():
    if "--list-tasks" in sys.argv:
        list_tasks()
        return

    if "--once" in sys.argv:
        sync()
        return

    scheduler = BlockingScheduler(timezone="UTC")
    sync()

    scheduler.add_job(
        sync,
        "interval",
        seconds=SYNC_INTERVAL,
        id="greenbone-defectdojo-sync",
        max_instances=1,
        coalesce=True,
    )

    log.info("Scheduler started. Sync interval: %s seconds", SYNC_INTERVAL)

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("Scheduler stopped")


if __name__ == "__main__":
    main()
