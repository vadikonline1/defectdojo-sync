"""Wazuh -> DefectDojo (parte din imaginea all-in-one)."""
import hashlib
import json
import os
from pathlib import Path

import requests
from packaging import version as pkg_version
from requests.auth import HTTPBasicAuth

from common import dd_check, dd_headers, get_logger

try:
    from opensearchpy import OpenSearch
    from opensearchpy.exceptions import OpenSearchException
    HAS_OPENSEARCH = True
except ImportError:  # pragma: no cover
    HAS_OPENSEARCH = False

log = get_logger("wazuh-sync")

WAZUH_BASE_URL = os.getenv(
    "WAZUH_BASE_URL", "https://wazuh.example.local:55000").rstrip("/")
WAZUH_USERNAME = os.getenv("WAZUH_USERNAME", "")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")
WAZUH_VERIFY_TLS = os.getenv("WAZUH_VERIFY_TLS", "false").lower() == "true"
WAZUH_GROUP = os.getenv("WAZUH_GROUP", "").strip()
WAZUH_AGENT_LIMIT = int(os.getenv("WAZUH_AGENT_LIMIT", "100000"))
WAZUH_MIN_SEVERITY = os.getenv("WAZUH_MIN_SEVERITY", "").strip()

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
OPENSEARCH_USERNAME = os.getenv("OPENSEARCH_USERNAME", "")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "")
OPENSEARCH_VERIFY_TLS = os.getenv("OPENSEARCH_VERIFY_TLS", "false").lower() == "true"
OPENSEARCH_INDEX = os.getenv("OPENSEARCH_INDEX", "wazuh-states-vulnerabilities-*")

WAZUH_PRODUCT = os.getenv("WAZUH_PRODUCT", "Wazuh")
WAZUH_PRODUCT_TYPE = os.getenv("WAZUH_PRODUCT_TYPE", "Security Scanning")
WAZUH_ENGAGEMENT = os.getenv("WAZUH_ENGAGEMENT", "Wazuh Automated Scans")
WAZUH_SCAN_TYPE = os.getenv("WAZUH_SCAN_TYPE", "Wazuh")
WAZUH_TEST_TITLE = os.getenv("WAZUH_TEST_TITLE", "Wazuh vulnerabilities")
# NU inchide automat findings lipsa din importul curent. Importul se face in
# chunkuri (< 100 MB); cu close_old_findings=true fiecare chunk ar inchide
# findings-urile celorlalte chunkuri -> Closed umflat artificial. Inchiderea
# se face doar manual sau cand remedierea e confirmata.
WAZUH_CLOSE_OLD_FINDINGS = os.getenv("WAZUH_CLOSE_OLD_FINDINGS", "false").lower() == "true"

WAZUH_REPORT_DIR = Path(os.getenv("WAZUH_REPORT_DIR", "/data/wazuh-reports"))
WAZUH_STATE_FILE = Path(os.getenv(
    "WAZUH_STATE_FILE", "/data/state/wazuh-sync-state.json"))
MAX_FINDINGS_PER_IMPORT = int(os.getenv("MAX_FINDINGS_PER_IMPORT", "15000"))


class WazuhError(RuntimeError):
    pass


def wazuh_headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def wazuh_authenticate():
    if not WAZUH_USERNAME or not WAZUH_PASSWORD:
        raise WazuhError("WAZUH_USERNAME sau WAZUH_PASSWORD lipsa in .env")
    if ":55000" not in WAZUH_BASE_URL:
        log.warning("WAZUH_BASE_URL pare URL de dashboard fara :55000. "
                    "API-ul Wazuh e de obicei pe https://<host>:55000")
    url = f"{WAZUH_BASE_URL}/security/user/authenticate?raw=true"
    try:
        r = requests.get(url, auth=HTTPBasicAuth(WAZUH_USERNAME, WAZUH_PASSWORD),
                         verify=WAZUH_VERIFY_TLS, timeout=30)
    except requests.RequestException as e:
        raise WazuhError(f"Nu pot ajunge la Wazuh API {url}: {e}") from e
    if r.status_code == 401:
        raise WazuhError(f"Wazuh auth 401 Unauthorized — user/parola gresite ({url})")
    if r.status_code == 404:
        raise WazuhError(f"Wazuh auth 404 — BASE_URL gresit. Foloseste "
                         f"URL-ul API cu portul :55000 (ai: {WAZUH_BASE_URL})")
    if r.status_code >= 400:
        raise WazuhError(f"Wazuh auth failed HTTP {r.status_code}: {r.text[:500]}")
    token = r.text.strip()
    if not token:
        raise WazuhError("Wazuh a returnat token gol")
    log.info("Wazuh authentication OK")
    return token


def wazuh_get(path, token, params=None):
    url = f"{WAZUH_BASE_URL}{path}"
    r = requests.get(url, headers=wazuh_headers(token),
                     params=params or {}, verify=WAZUH_VERIFY_TLS, timeout=30)
    if r.status_code == 401:  # token expirat, re-auth o data
        token = wazuh_authenticate()
        r = requests.get(url, headers=wazuh_headers(token),
                         params=params or {}, verify=WAZUH_VERIFY_TLS, timeout=30)
    return r, token


def get_wazuh_version(token):
    r, token = wazuh_get("/manager/info", token)
    if r.status_code >= 400:
        raise WazuhError(f"/manager/info HTTP {r.status_code}: {r.text[:500]}")
    items = r.json().get("data", {}).get("affected_items", [])
    ver = items[0].get("version") if items else None
    log.info("Wazuh version: %s", ver)
    return ver or "0.0.0", token


def get_agents(token):
    if WAZUH_GROUP:
        log.info("Listeaza agentii din grupul %r", WAZUH_GROUP)
        r, token = wazuh_get(f"/groups/{WAZUH_GROUP}/agents", token,
                             params={"limit": WAZUH_AGENT_LIMIT})
        if r.status_code == 404:
            raise WazuhError(f"Grupul Wazuh {WAZUH_GROUP!r} nu exista (404). "
                             f"Lasa WAZUH_GROUP gol pentru toti agentii.")
        if r.status_code >= 400:
            raise WazuhError(f"/groups agents HTTP {r.status_code}: {r.text[:500]}")
        agents = r.json().get("data", {}).get("affected_items", [])
    else:
        log.info("Listeaza toti agentii")
        r, token = wazuh_get("/agents", token,
                             params={"limit": WAZUH_AGENT_LIMIT, "select": "id,name,ip"})
        if r.status_code >= 400:
            raise WazuhError(f"/agents HTTP {r.status_code}: {r.text[:500]}")
        agents = r.json().get("data", {}).get("affected_items", [])
    log.info("Gasiti %d agenti", len(agents))
    return agents, token


def opensearch_client():
    if not HAS_OPENSEARCH:
        raise WazuhError("lipseste pachetul opensearch-py (requirements.txt)")
    if not (OPENSEARCH_HOST and OPENSEARCH_USERNAME and OPENSEARCH_PASSWORD):
        raise WazuhError(
            "Pentru Wazuh >= 4.8 trebuie OPENSEARCH_HOST/USERNAME/PASSWORD in .env. "
            "Fara ele primesti 'OpenSearch client is not configured' / "
            "'First page is empty' / 404 pe /vulnerability/{agent}.")
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        use_ssl=True,
        http_auth=(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD),
        verify_certs=OPENSEARCH_VERIFY_TLS,
        timeout=30,
    )


def fetch_vulns_opensearch(agent_ids):
    """Returneaza payload OpenSearch brut {"hits": {"hits": [...]}} (format DefectDojo v4_8)."""
    client = opensearch_client()
    query = {"query": {"bool": {
        "must": [{"terms": {"agent.id": agent_ids}}],
        "should": [{"match": {"vulnerability.severity": s}}
                   for s in ("Critical", "High", "Medium", "Low")],
    }}}
    log.info("Query OpenSearch %s/%s pentru %d agenti", OPENSEARCH_HOST,
             OPENSEARCH_INDEX, len(agent_ids))
    try:
        page = client.search(body=query, index=OPENSEARCH_INDEX, scroll="1m", size=10000)
    except OpenSearchException as e:
        raise WazuhError(f"OpenSearch search failed: {e}. Verifica indexul "
                         f"{OPENSEARCH_INDEX!r} si creds.") from e
    if not page or not page.get("_scroll_id"):
        raise WazuhError("OpenSearch nu a returnat _scroll_id (First page is empty?). "
                         "Cauze: index gresit, fara vulnerabilitati, sau permisiuni.")
    scroll_id = page["_scroll_id"]
    total = (page.get("hits", {}).get("total") or {}).get("value")
    log.info("OpenSearch total hits: %s", total)
    all_hits = list(page.get("hits", {}).get("hits", []))
    try:
        while True:
            nxt = client.scroll(scroll_id=scroll_id, scroll="1m")
            scroll_id = nxt.get("_scroll_id", scroll_id)
            hits = nxt.get("hits", {}).get("hits", [])
            if not hits:
                break
            all_hits.extend(hits)
            if total and len(all_hits) >= total:
                break
    finally:
        try:
            client.clear_scroll(scroll_id=scroll_id)
        except Exception:
            pass
    log.info("OpenSearch hits colectate: %d", len(all_hits))
    return {"hits": {"hits": all_hits,
                     "total": {"value": len(all_hits), "relation": "eq"}}}


def fetch_vulns_legacy_api(agent_ids_names, token):
    """Fallback < 4.8: GET /vulnerability/{agent}. Pe 4.14 da 404."""
    items = []
    for aid, aname, aip in agent_ids_names:
        r, token = wazuh_get(f"/vulnerability/{aid}", token, params={"limit": 100000})
        if r.status_code == 404:
            raise WazuhError("Endpoint /vulnerability/{agent} da 404 — normal pe "
                             "Wazuh >= 4.8. Configureaza OpenSearch in .env.")
        if r.status_code == 400:
            continue
        if r.status_code >= 400:
            log.warning("Agent %s: HTTP %s", aid, r.status_code)
            continue
        for v in r.json().get("data", {}).get("affected_items", []):
            if v.get("condition") == "Package unfixed":
                continue
            v["agent_ip"] = aip
            v["agent_name"] = aname
            items.append(v)
    return {"data": {"affected_items": items, "total_affected_items": len(items)}}, token


def filter_severity(payload):
    if not WAZUH_MIN_SEVERITY:
        return payload
    allowed = {s.strip().capitalize() for s in WAZUH_MIN_SEVERITY.split(",") if s.strip()}
    if "hits" in payload:
        before = len(payload["hits"]["hits"])
        payload["hits"]["hits"] = [
            h for h in payload["hits"]["hits"]
            if (h.get("_source", {}).get("vulnerability", {}).get("severity", "") or "").capitalize() in allowed
        ]
        log.info("Filtru severitate %s: %d -> %d", allowed, before, len(payload["hits"]["hits"]))
    else:
        before = len(payload["data"]["affected_items"])
        payload["data"]["affected_items"] = [
            v for v in payload["data"]["affected_items"]
            if (v.get("severity", "") or "").capitalize() in allowed
        ]
        log.info("Filtru severitate %s: %d -> %d", allowed, before, len(payload["data"]["affected_items"]))
    return payload


def payload_fingerprint(payload):
    if "hits" in payload:
        keys = sorted(
            f"{h.get('_source', {}).get('vulnerability', {}).get('id', '')}-"
            f"{h.get('_source', {}).get('agent', {}).get('id', '')}-"
            f"{h.get('_source', {}).get('package', {}).get('name', '')}-"
            f"{h.get('_source', {}).get('package', {}).get('version', '')}"
            for h in payload["hits"]["hits"])
    else:
        keys = sorted(
            f"{v.get('cve', '')}-{v.get('agent_name', '')}-{v.get('name', '')}-{v.get('version', '')}"
            for v in payload["data"]["affected_items"])
    return hashlib.sha256("\n".join(keys).encode()).hexdigest(), len(keys)


def load_state():
    if WAZUH_STATE_FILE.exists():
        try:
            return json.loads(WAZUH_STATE_FILE.read_text())
        except Exception:
            return {}
    return {}


def save_state(fp, count):
    WAZUH_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    WAZUH_STATE_FILE.write_text(json.dumps({"fingerprint": fp, "count": count}))


def post_scan_file(json_path, first_file):
    from common import DEFECTDOJO_URL, DEFECTDOJO_VERIFY_TLS
    endpoints = ("reimport-scan", "import-scan") if first_file else ("reimport-scan",)
    last_err = None
    for endpoint in endpoints:
        url = f"{DEFECTDOJO_URL}/api/v2/{endpoint}/"
        data = {
            "scan_type": WAZUH_SCAN_TYPE,  # "Wazuh" nativ
            "product_name": WAZUH_PRODUCT,
            "product_type_name": os.getenv("DEFECTDOJO_PRODUCT_TYPE", "Security Scanning"),
            "engagement_name": WAZUH_ENGAGEMENT,
            "test_title": WAZUH_TEST_TITLE,
            "auto_create_context": "true",
            "active": "true",
            "verified": "false",
            "minimum_severity": "Info",
            "tags": "wazuh",
            "close_old_findings": "true" if WAZUH_CLOSE_OLD_FINDINGS else "false",
        }
        size_mb = json_path.stat().st_size / 1048576
        log.info("Upload %s (%.1f MB) -> %s", json_path.name, size_mb, endpoint)
        with json_path.open("rb") as f:
            r = requests.post(url, headers=dd_headers(), data=data,
                              files={"file": (json_path.name, f, "application/json")},
                              verify=DEFECTDOJO_VERIFY_TLS, timeout=600)
        if r.status_code < 400:
            log.info("DefectDojo %s OK: HTTP %s", endpoint, r.status_code)
            return r
        last_err = f"HTTP {r.status_code}: {r.text[:500]}"
        if endpoint == "reimport-scan" and r.status_code in (400, 404) and first_file:
            log.info("reimport-scan HTTP %s, incerc import-scan...", r.status_code)
            continue
        raise RuntimeError(f"DefectDojo {endpoint} {last_err[:2000]}")
    raise RuntimeError(f"DefectDojo import esuat: {last_err}")


def import_into_defectdojo(json_paths):
    if isinstance(json_paths, Path):
        json_paths = [json_paths]
    for i, p in enumerate(json_paths):
        post_scan_file(p, first_file=(i == 0))
        log.info("Chunk %d/%d importat", i + 1, len(json_paths))


def chunk_payload(payload, max_per_file):
    """Imparte payload-ul in fisiere < 100MB (limita DefectDojo)."""
    if "hits" in payload:
        hits = payload["hits"]["hits"]
        if len(hits) <= max_per_file:
            return [payload]
        chunks = []
        for i in range(0, len(hits), max_per_file):
            part = hits[i:i + max_per_file]
            chunks.append({"hits": {"hits": part,
                                    "total": {"value": len(part), "relation": "eq"}}})
        return chunks
    items = payload["data"]["affected_items"]
    if len(items) <= max_per_file:
        return [payload]
    return [{"data": {"affected_items": items[i:i + max_per_file],
                      "total_affected_items": len(items[i:i + max_per_file])}}
            for i in range(0, len(items), max_per_file)]


def collect_payload():
    token = wazuh_authenticate()
    ver, token = get_wazuh_version(token)
    agents, token = get_agents(token)
    if not agents:
        log.warning("Niciun agent — nimic de exportat")
        return {"hits": {"hits": [], "total": {"value": 0}}}, "0", 0
    agent_ids = [a.get("id") for a in agents if a.get("id")]
    if pkg_version.parse(ver) >= pkg_version.parse("4.8.0"):
        payload = fetch_vulns_opensearch(agent_ids)
    else:
        triples = [(a.get("id"), a.get("name"), a.get("ip")) for a in agents]
        payload, _ = fetch_vulns_legacy_api(triples, token)
    payload = filter_severity(payload)
    fp, count = payload_fingerprint(payload)
    return payload, fp, count


def wazuh_sync():
    log.info("========== Wazuh -> DefectDojo sync started ==========")
    dd_check(log)
    payload, fp, count = collect_payload()
    log.info("Vulnerabilitati colectate: %d (fp %s...)", count, fp[:12])
    state = load_state()
    if state.get("fingerprint") == fp and count > 0:
        log.info("Nicio schimbare fata de rularea anterioara — skip import (anti-duplicat)")
        return
    if count == 0:
        log.warning("0 vulnerabilitati — skip import")
        save_state(fp, count)
        return
    # DefectDojo refuza fisiere > 100MB -> chunking (~15k findings ~= 44MB)
    WAZUH_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    parts = chunk_payload(payload, MAX_FINDINGS_PER_IMPORT)
    log.info("Impartit in %d chunkuri (max %d findings/chunk)", len(parts), MAX_FINDINGS_PER_IMPORT)
    paths = []
    for i, part in enumerate(parts, 1):
        p = WAZUH_REPORT_DIR / f"wazuh_part_{i:03d}.json"
        p.write_text(json.dumps(part))
        log.info("Salvat %s (%d bytes)", p, p.stat().st_size)
        paths.append(p)
    import_into_defectdojo(paths)
    save_state(fp, count)
    log.info("========== Wazuh finished: %d findings in %d chunks ==========", count, len(paths))


def wazuh_list_agents():
    token = wazuh_authenticate()
    ver, token = get_wazuh_version(token)
    agents, _ = get_agents(token)
    print(f"\nWazuh {ver} — {len(agents)} agenti:")
    print("-" * 80)
    for a in agents[:50]:
        print(f"{a.get('id')} | {a.get('name')} | {a.get('ip')} | {a.get('status')}")
    if len(agents) > 50:
        print(f"... si alti {len(agents) - 50}")
