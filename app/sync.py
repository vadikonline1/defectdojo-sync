"""Orchestrator all-in-one: openvas_sync + wazuh_sync in acelasi container.

Utilizare:
  python -m sync --once [--only openvas|wazuh]
  python -m sync --list-tasks     # taskuri Greenbone/OpenVAS
  python -m sync --list-agents    # agenti Wazuh
  python -m sync                  # scheduler periodic (ambele)
"""
import sys
import traceback

from apscheduler.schedulers.blocking import BlockingScheduler

from common import SYNC_INTERVAL, get_logger, init_storage
from openvas_sync import OPENVAS_REPORT_DIR, openvas_list_tasks, openvas_sync
from wazuh_sync import WAZUH_REPORT_DIR, WAZUH_STATE_FILE, wazuh_list_agents, wazuh_sync

log = get_logger("defectdojo-sync")


def run_all():
    for name, fn in (("openvas", openvas_sync), ("wazuh", wazuh_sync)):
        try:
            fn()
        except Exception:
            log.error("Sync %s esuat (celalalt continua):", name)
            traceback.print_exc()


def run_once_only(which):
    if which == "openvas":
        openvas_sync()
    elif which == "wazuh":
        wazuh_sync()
    else:
        raise SystemExit("--only trebuie sa fie openvas sau wazuh")


def main():
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
