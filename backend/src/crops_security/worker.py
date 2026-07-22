import logging
import signal
from threading import Event

from .health import redis_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)
stop = Event()


def request_stop(*_: object) -> None:
    stop.set()


def main() -> None:
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    client = redis_client()
    logger.info("CropsSecurity worker started")
    while not stop.is_set():
        client.set("cropssecurity:worker:heartbeat", "online", ex=15)
        stop.wait(5)
    logger.info("CropsSecurity worker stopped")


if __name__ == "__main__":
    main()

