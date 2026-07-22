from .health import worker_is_ready

if __name__ == "__main__":
    raise SystemExit(0 if worker_is_ready() else 1)
