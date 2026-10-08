"""OpenVAS/Greenbone -> DefectDojo (parte din imaginea all-in-one)."""
import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
from xml.etree import ElementTree as ET

from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import GMP
from gvm.transforms import EtreeCheckCommandTransform

from common import (
    DEFECTDOJO_ENGAGEMENT_DEFAULT,
    DEFECTDOJO_PRODUCT_DEFAULT,
    dd_check,
    dd_post_scan,
    get_logger,
)

log = get_logger("openvas-sync")

GVM_SOCKET = os.getenv("GVM_SOCKET", "/run/gvmd/gvmd.sock")
GVM_USERNAME = os.getenv("GVM_USERNAME", "admin")
GVM_PASSWORD = os.getenv("GVM_PASSWORD", "")

OPENVAS_PRODUCT = os.getenv("OPENVAS_PRODUCT", DEFECTDOJO_PRODUCT_DEFAULT)
OPENVAS_PRODUCT_TYPE = os.getenv("OPENVAS_PRODUCT_TYPE", "Security Scanning")
OPENVAS_ENGAGEMENT = os.getenv("OPENVAS_ENGAGEMENT", "Greenbone Automated Scans")
# NOTE: "OpenVAS Parser v2" crasheaza in DefectDojo (cleanup_openvas_text(None)
# cand <solution/> e gol). Foloseste v1 "OpenVAS Parser".
OPENVAS_SCAN_TYPE = os.getenv("OPENVAS_SCAN_TYPE", "OpenVAS Parser")

OPENVAS_REPORT_DIR = Path(os.getenv("OPENVAS_REPORT_DIR", "/data/openvas-reports"))
OPENVAS_STATE_FILE = Path(os.getenv(
    "OPENVAS_STATE_FILE", str(OPENVAS_REPORT_DIR / "sync-state.txt")))
OPENVAS_ONLY_FINISHED = os.getenv("OPENVAS_ONLY_FINISHED", "true").lower() == "true"


@contextmanager
def gmp_session():
    """Sesiune GMP autentificata (python-gvm >= 25 cere context manager)."""
    if not GVM_USERNAME or not GVM_PASSWORD:
        raise RuntimeError("GVM_USERNAME sau GVM_PASSWORD lipsa")
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
        tasks.append({"id": task_id, "name": name,
                      "status": status, "report_id": report_id})
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
            f"Greenbone response does not contain wrapper report for {report_id}")
    # Parserul DefectDojo "OpenVAS Parser" asteapta wrapper-ul EXTERN:
    # <report format_id=...><report id=...><results>...
    report_payload = wrapper_report.find("report")
    if report_payload is None:
        raise RuntimeError(
            f"Greenbone response does not contain nested report payload for {report_id}")
    if report_payload.find("results") is None:
        raise RuntimeError(
            f"Nested report payload for {report_id} has no <results>")
    xml_bytes = ET.tostring(wrapper_report, encoding="utf-8", xml_declaration=True)
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise RuntimeError(f"Extracted OpenVAS report is not valid XML: {exc}") from exc
    if root.tag != "report":
        raise RuntimeError(f"Unexpected OpenVAS XML root element: {root.tag!r}")
    nested = root.find("report")
    if nested is None or nested.find("results") is None:
        raise RuntimeError(
            f"Extracted XML for {report_id} does not match DefectDojo "
            "OpenVAS Parser structure (report/report/results)")
    log.info("Extracted OpenVAS report wrapper: id=%s", report_id)
    log.info("OpenVAS XML validated successfully: %d bytes", len(xml_bytes))
    return xml_bytes


def load_state():
    if not OPENVAS_STATE_FILE.exists():
        return set()
    return {l.strip() for l in
            OPENVAS_STATE_FILE.read_text(encoding="utf-8").splitlines() if l.strip()}


def save_state(report_id):
    OPENVAS_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    with OPENVAS_STATE_FILE.open("a", encoding="utf-8") as f:
        f.write(report_id + "\n")


def save_report(report_id, xml_bytes):
    OPENVAS_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = OPENVAS_REPORT_DIR / f"{report_id}.xml"
    path.write_bytes(xml_bytes)
    log.info("Saved OpenVAS XML: %s", path)
    return path


def import_into_defectdojo(xml_path, task_name, report_id):
    data = {
        "scan_type": OPENVAS_SCAN_TYPE,
        "product_name": OPENVAS_PRODUCT,
        "product_type_name": OPENVAS_PRODUCT_TYPE,
        "engagement_name": OPENVAS_ENGAGEMENT,
        "test_title": f"Greenbone - {task_name}",
        "auto_create_context": "true",
        "active": "true",
        "verified": "false",
        "minimum_severity": "Info",
        "tags": f"greenbone,task:{task_name},report:{report_id}",
    }
    return dd_post_scan(log, "reimport-scan", data, xml_path, timeout=300)


def openvas_sync():
    log.info("========== OpenVAS -> DefectDojo sync started ==========")
    dd_check(log)
    with gmp_session() as gmp:
        ver = gmp.get_version()
        gmp_version = ver.findtext("version") if hasattr(ver, "findtext") else ver.text
        log.info("Greenbone GMP version: %s (negotiated %s)",
                 gmp_version, type(gmp).__name__)
        fmt_id, fmt_name = get_report_formats(gmp)
        log.info("Using Greenbone report format: %s (%s)", fmt_name, fmt_id)
        tasks = get_tasks(gmp)
        log.info("Found %d Greenbone tasks", len(tasks))
        state = load_state()
        imported = skipped = 0
        for task in tasks:
            task_id, task_name = task["id"], task["name"]
            status, report_id = task["status"], task["report_id"]
            log.info("Task: id=%s name=%r status=%s report_id=%s",
                     task_id, task_name, status, report_id)
            if OPENVAS_ONLY_FINISHED and status.lower() not in {"done", "stopped"}:
                log.info("Skipping unfinished task %s (%s)", task_id, status)
                skipped += 1
                continue
            if not report_id:
                skipped += 1
                continue
            if report_id in state:
                log.info("Skipping report %s: already imported", report_id)
                skipped += 1
                continue
            try:
                xml_bytes = get_report_xml(gmp, report_id, fmt_id)
                log.info("Report SHA256: %s",
                         hashlib.sha256(xml_bytes).hexdigest())
                xml_path = save_report(report_id, xml_bytes)
                ET.parse(str(xml_path))
                import_into_defectdojo(xml_path, task_name, report_id)
                save_state(report_id)
                state.add(report_id)
                imported += 1
            except Exception:
                log.exception("Failed task %s / report %s", task_id, report_id)
        log.info("========== OpenVAS finished: imported=%d skipped=%d ==========",
                 imported, skipped)


def openvas_list_tasks():
    dd_check(log)
    with gmp_session() as gmp:
        tasks = get_tasks(gmp)
        print("\nGreenbone tasks:")
        print("-" * 100)
        for t in tasks:
            print(f"{t['id']} | {t['status']:<10} | {t['name']} | report={t['report_id']}")
        print("-" * 100)
