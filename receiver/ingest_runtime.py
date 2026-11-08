"""Shared defaults for the receiver and its read-only health endpoint."""

import os


def status_path():
    """Health is disposable IPC; only the retry spool needs persistent storage.

    Docker supplies /dev/shm as tmpfs. Keep explicit paths for existing
    installations and the /run fallback for platforms without shared memory.
    """
    if 'INGEST_STATUS_PATH' in os.environ:
        return os.environ['INGEST_STATUS_PATH']
    root = '/dev/shm' if os.path.isdir('/dev/shm') else '/run'
    return f'{root}/unifi-log-insight/receiver-health.json'


# At the socket's 8 KiB receive limit this is at most 128 MiB of payload,
# plus Python queue/address overhead. Memory before staging is not durable.
DEFAULT_QUEUE_CAPACITY = 16384
