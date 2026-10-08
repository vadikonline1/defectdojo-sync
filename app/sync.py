"""Orchestrator all-in-one: openvas_sync + wazuh_sync in acelasi container.

Utilizare:
  python -m sync --once [--only openvas|wazuh]
  python -m sync --list-tasks     # taskuri Greenbone/OpenVAS
  python -m sync --list-agents    # agenti Wazuh
  python -m sync                  # scheduler periodic (ambele)
"""
import os
import sys
import traceback

from apscheduler.schedulers.blocking import BlockingScheduler

from common import SYNC_INTERVAL, get_logger, init_storage
from openvas_sync import OPENVAS_REPORT_DIR, openvas_list_tasks, openvas_sync
from wazuh_sync import WAZUH_REPORT_DIR, WAZUH_STATE_FILE, wazuh_list_agents, wazuh_sync

log = get_logger("defectdojo-sync")

# Surse active, separate prin virgula. Daca nu ai un sistem, scoate-l din
# lista si nu va mai fi interogat (fara erori in log la fiecare rulare).
# Ex: ENABLED_SOURCES=openvas  sau  ENABLED_SOURCES=wazuh
ENABLED_SOURCES = {s.strip().lower() for s in
                   os.getenv("ENABLED_SOURCES", "openvas,wazuh").split(",") if s.strip()}


def is_enabled(name):
    return name in ENABLED_SOURCES


def run_all():
    for name, fn in (("openvas", openvas_sync), ("wazuh", wazuh_sync)):
        if not is_enabled(name):
            log.info("Sursa %s dezactivata prin ENABLED_SOURCES — skip", name)
            continue
        try:
            fn()
        except Exception:
            log.error("Sync %s esuat (celalalt continua):", name)
            traceback.print_exc()


def run_once_only(which):
    if which not in ("openvas", "wazuh"):
        raise SystemExit("--only trebuie sa fie openvas sau wazuh")
    if not is_enabled(which):
        raise SystemExit(f"Sursa {which} e dezactivata prin ENABLED_SOURCES={','.join(sorted(ENABLED_SOURCES))}")
    openvas_sync() if which == "openvas" else wazuh_sync()


def main():
    log.info("Surse active: %s", ",".join(sorted(ENABLED_SOURCES)) or "(niciuna!)")
    init_storage(log, [str(OPENVAS_REPORT_DIR),
                       str(WAZUH_REPORT_DIR),
                       str(WAZUH_STATE_FILE.parent)])
    if "--list-tasks" in sys.argv:
        openvas_list_tasks()
        return
    if "--list-agents" in sys.argv:
        wazuh_list_agents()
        return
    if "--once" in sys.argv:
        if "--only" in sys.argv:
            run_once_only(sys.argv[sys.argv.index("--only") + 1])
        else:
            run_all()
        return
    scheduler = BlockingScheduler(timezone="UTC")
    run_all()
    scheduler.add_job(run_all, "interval", seconds=SYNC_INTERVAL,
                      id="defectdojo-sync", max_instances=1, coalesce=True)
    log.info("Scheduler started. Interval: %s secunde (openvas + wazuh)", SYNC_INTERVAL)
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("Scheduler stopped")


if __name__ == "__main__":
    main()
