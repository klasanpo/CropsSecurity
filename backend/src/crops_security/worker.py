import logging
import signal
from datetime import UTC, datetime
from threading import Event

from .database import (
    get_scan,
    initialize_database,
    now_iso,
    save_findings,
    scan_cancelled,
    update_scan,
)
from .health import redis_client
from .tools.web.sensitive_data import ScanOptions, SensitiveDataScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)
stop = Event()


def request_stop(*_: object) -> None:
    stop.set()


def execute_scan(scan_id: str) -> None:
    scan = get_scan(scan_id)
    if not scan or scan["status"] != "queued":
        return
    if scan["cancel_requested"]:
        update_scan(
            scan_id, status="cancelled", progress=0, phase="Cancelado", finished_at=now_iso()
        )
        return

    parameters = scan["parameters"]
    options = ScanOptions(
        max_urls=parameters["max_urls"],
        depth=parameters["depth"],
        timeout_seconds=parameters["timeout_seconds"],
        max_resource_bytes=parameters["max_resource_bytes"],
        include_external=parameters["include_external"],
        verify_tls=parameters["verify_tls"],
        custom_words=tuple(parameters.get("custom_words", [])),
    )
    update_scan(
        scan_id,
        status="running",
        progress=3,
        phase="Preparando análise",
        started_at=datetime.now(UTC).isoformat(),
    )

    def report(progress: int, phase: str, pages: int) -> None:
        update_scan(scan_id, progress=progress, phase=phase, pages_scanned=pages)

    try:
        outcome = SensitiveDataScanner(options).run(
            scan["target"],
            progress=report,
            cancelled=lambda: scan_cancelled(scan_id) or stop.is_set(),
        )
        if scan_cancelled(scan_id) or stop.is_set():
            update_scan(
                scan_id,
                status="cancelled",
                phase="Cancelado pelo operador",
                pages_scanned=outcome.pages_scanned,
                findings_count=len(outcome.findings),
                finished_at=now_iso(),
            )
            return
        update_scan(
            scan_id, progress=90, phase="Salvando achados", pages_scanned=outcome.pages_scanned
        )
        save_findings(scan_id, outcome.findings)
        error_summary = "\n".join(outcome.errors[:20]) or None
        update_scan(
            scan_id,
            status="completed",
            progress=100,
            phase="Concluído",
            pages_scanned=outcome.pages_scanned,
            findings_count=len(outcome.findings),
            error=error_summary,
            finished_at=now_iso(),
        )
        logger.info("Scan %s completed with %d findings", scan_id, len(outcome.findings))
    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        update_scan(
            scan_id,
            status="failed",
            phase="Falha na execução",
            error=str(exc),
            finished_at=now_iso(),
        )


def main() -> None:
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    initialize_database()
    client = redis_client()
    logger.info("CropsSecurity worker started")
    while not stop.is_set():
        client.set("cropssecurity:worker:heartbeat", "online", ex=15)
        item = client.brpop("cropssecurity:scan_queue", timeout=5)
        if item:
            execute_scan(str(item[1]))
    logger.info("CropsSecurity worker stopped")


if __name__ == "__main__":
    main()
