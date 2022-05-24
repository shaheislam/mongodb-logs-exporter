# pylint: disable=E1101

from io import StringIO
from os import environ
from datetime import datetime, timezone
import logging
import json
import boto3

"""
Establishes connection to the bucket and formats the data to bytearray
(s3 bucket only accepts byte or bytearray format)
"""


def _write_events(object_id, events):
    events = list(events)
    assert events, "Expected at least 1 event as we include heartbeats"
    out = StringIO()
    for event in events:
        line = json.dumps(event)
        out.write(line)
        out.write("\n")
        logging.debug(line)
    out = out.getvalue()
    s3 = boto3.resource("s3")
    s3.Object(environ["ATLAS_LOG_BUCKET"], object_id).put(Body=out)
    logging.debug("Written %s events to %s", len(events), object_id)


"""
Adds a timestamp to the data (called events) before it is sent the s3 bucket
"""


def _append_heartbeat(events, date):
    result = events.copy()
    result.append(
        {"created": date.isoformat(), "eventTypeName": "@ATLAS_LOG_TO_S3_HEARTBEAT"}
    )
    return result


"""
Writes to the s3 bucket
"""


def write_logs(group_id, hostname, log, events, page, chunk):
    now = datetime.now(tz=timezone.utc)
    events = _append_heartbeat(events, now)
    log = log.split(".")[0]
    # First argument defines s3 bucket structure
    _write_events(
        f"NdapAtlasLogs/logs/{log}/{group_id}_{hostname}_page_{page}_chunk_{chunk}_{int(now.timestamp())}.log",
        events,
    )


def write_any_events(type_id, events, page_no, process):
    now = datetime.now(tz=timezone.utc)
    events = _append_heartbeat(events, now)
    _write_events(
        f"NdapAtlasLogs/logs/{process}s/{type_id}_pageno_{page_no}_{int(now.timestamp())}.log",
        events,
    )


def write_access_history(group_id, clusternames, events, page, chunk):
    now = datetime.now(tz=timezone.utc)
    events = _append_heartbeat(events, now)
    _write_events(
        f"NdapAtlasLogs/logs/access-history/{group_id}_clusternames_{clusternames}_page_{page}_chunk_{chunk}_{int(now.timestamp())}.log",
        events,
    )
