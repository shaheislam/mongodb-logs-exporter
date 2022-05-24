# pylint: disable=E1101

import logging
import requests
from os import environ
from requests.auth import HTTPDigestAuth
import json
import gzip
import hashlib
from datetime import datetime, timezone
import calendar
from prometheus_client import Histogram, Counter

MONGO_API_ROOT = "https://cloud.mongodb.com/api/atlas/v1.0/"
request_time_histogram = Histogram(
    "atlas_log_exporter_api_request_latency_seconds",
    "The time for atlas requests",
    ["route_name"],
)
request_response_status = Counter(
    "atlas_log_exporter_api_response_codes",
    "The response codes received when calling the atlas API",
    ["route_name", "status"],
)
no_hwm_startdate_trigger = Counter(
    "atlas_log_exporter_no_hwm_start_date", "HWM startdate not found",
)


def mk_auth():
    return HTTPDigestAuth(environ["ATLAS_USERNAME"], environ["ATLAS_APIKEY"])


def convert_mongodb_logs_and_generate_id(
    raw_logs, hostname, database_name, project_name
):
    json_logs = []
    try:
        for log in raw_logs:
            hashed_text = hashlib.sha256(log.encode("utf-8"))
            hex_digest = hashed_text.hexdigest()
            log = " ".join(log.split())
            split_log = log.split(" ", 4)
            timestamp = split_log[0]
            severity = split_log[1]
            component = split_log[2]
            context = split_log[3][1:-1]
            message = split_log[4]

            json_logs.append(
                {
                    "id": hex_digest,
                    "hostname": hostname,
                    "created": timestamp,
                    "severity": severity,
                    "component": component,
                    "context": context,
                    "message": message,
                    "database": database_name,
                    "project": project_name,
                }
            )
        logging.debug("Converted %s non-JSON logs and generated ids", len(raw_logs))
    except:
        logging.info("-------------------------------------")
        logging.info("%s could not be processed", raw_logs)
        logging.info("-------------------------------------")

    return json_logs


def convert_audit_logs_and_generate_id(logs, hostname, database_name, project_name):
    json_logs = []

    try:
        for log in logs:
            timestamp = json.loads(log)["ts"]["$date"]
            hashed_text = hashlib.sha256(log.encode("utf-8"))
            hex_digest = hashed_text.hexdigest()
            json_logs.append(
                {
                    "id": hex_digest,
                    "hostname": hostname,
                    "created": timestamp,
                    "audit_dump": json.loads(log),
                    "database": database_name,
                    "project": project_name,
                }
            )
        logging.debug("Converted %s non-JSON logs and generated ids", len(logs))
    except:
        logging.info("-------------------------------------")
        logging.info("%s could not be processed", logs)
        logging.info("-------------------------------------")

    return json_logs


def convert_access_history_logs_and_generate_id(logs, clustername, project_name):
    json_logs = []

    try:
        for log in logs:
            logline = log["logLine"]
            split_logline = logline.split(" ", 1)
            timestamp = split_logline[0]
            hashed_text = hashlib.sha256(json.dumps(log).encode("utf-8"))
            hex_digest = hashed_text.hexdigest()
            json_logs.append(
                {
                    "id": hex_digest,
                    "created": timestamp,
                    "access_dump": log,
                    "database": clustername,
                    "project": project_name,
                }
            )
        logging.debug("Converted %s access logs and generated ids", len(logs))
    except:
        logging.info("-------------------------------------")
        logging.info("%s could not be processed", logs)
        logging.info("-------------------------------------")

    return json_logs


def doJsonGet(route_name, url, key="results", params={}, headers={}):
    with request_time_histogram.labels(url).time():
        r = requests.get(
            MONGO_API_ROOT + url, auth=mk_auth(), params=params, headers=headers
        )

    request_response_status.labels(url, r.status_code).inc()
    r.raise_for_status()
    return r.json()[key]


def doGZipGet(route_name, url, params={}):
    with request_time_histogram.labels(route_name).time():
        r = requests.get(
            MONGO_API_ROOT + url,
            auth=mk_auth(),
            params=params,
            headers={"Accept": "application/gzip"},
        )

    request_response_status.labels(route_name, r.status_code).inc()
    r.raise_for_status()
    return gzip.decompress(r.content)


def uri_deconstruct(uri):
    hostnames = []
    for i in uri:
        if "://" in i:
            temp = i.split("://", 1)[1]
            temp = temp.split(":", 1)[0]
        else:
            temp = i.split(":", 1)[0]
        hostnames.append(temp)
    return hostnames


def get_clusters(group_id):
    results = doJsonGet("group_clusters", f"groups/{group_id}/clusters")
    logging.debug("Retrieved %s clusters for group %s", len(results), group_id)
    return results


def get_groups():
    results = doJsonGet("groups", "groups")
    logging.debug("Retrieved %s groups", len(results))
    return results


def get_orgs():
    results = doJsonGet("orgs", "orgs")
    logging.debug("Retrieved %s orgs", len(results))
    return results


def get_org_events(org_id, min_datetime, max_datetime):
    page_no = 1
    data_from_mongo = True
    items_per_page = 500
    while data_from_mongo:
        params = {
            "minDate": min_datetime,
            "itemsPerPage": items_per_page,
            "pageNum": page_no,
            "maxDate": max_datetime,
        }
        results = doJsonGet("org_events", f"orgs/{org_id}/events", params=params)

        logging.debug(
            "Retrieved %s events for org %s, page number %s, since %s",
            len(results),
            org_id,
            page_no,
            min_datetime,
        )
        if len(results) < items_per_page:
            data_from_mongo = False
        else:
            page_no += 1

        yield results


def get_group_events(group_id, min_datetime, max_datetime):
    page_no = 1
    data_from_mongo = True
    items_per_page = 500
    while data_from_mongo:
        params = {
            "minDate": min_datetime,
            "itemsPerPage": items_per_page,
            "pageNum": page_no,
            "maxDate": max_datetime,
        }
        results = doJsonGet("group_events", f"groups/{group_id}/events", params=params)

        logging.debug(
            "Could not retrieve %s events for group %s, page number %s, since %s",
            len(results),
            group_id,
            page_no,
            min_datetime,
        )
        if len(results) < items_per_page:
            data_from_mongo = False
        else:
            page_no += 1

        yield results


def get_and_process_access_history(group_id, clustername, params, project_name):
    access_logs = doJsonGet(
        "access_history",
        f"groups/{group_id}/dbAccessHistory/clusters/{clustername}",
        key="accessLogs",
        params=params,
    )
    json_results = convert_access_history_logs_and_generate_id(
        access_logs, clustername, project_name
    )
    return json_results


def get_access_logs(
    group_id,
    clustername,
    start_datetime_in_unix_milliseconds,
    end_datetime_in_unix_milliseconds,
    project_name,
):
    params = None
    json_results = []

    if start_datetime_in_unix_milliseconds is None:
        json_results = get_and_process_access_history(
            group_id, clustername, params, project_name
        )

    else:
        params = {
            "start": start_datetime_in_unix_milliseconds,
            "end": end_datetime_in_unix_milliseconds,
        }

        json_results += get_and_process_access_history(
            group_id, clustername, params, project_name
        )

    logging.debug(
        "Retrieved %s access logs for group %s, cluster %s",
        len(json_results),
        group_id,
        clustername,
    )
    return json_results


def convert_timezone_to_utc_epoch(timestamp_string):
    timestamp = datetime.strptime(timestamp_string, "%Y-%m-%d %H:%M:%S")
    epoch = int(calendar.timegm(timestamp.utctimetuple()))
    return epoch


def utc_to_unix_milliseconds_datetime(start_datetime):
    if start_datetime is None:
        unix_datetime = None
    else:
        # Adding date and time together in milliseconds
        formatted_start_datetime = start_datetime.split(".")[0].replace("T", " ")
        unix_times = convert_timezone_to_utc_epoch(formatted_start_datetime)
        unix_datetime = (unix_times) * 1000
    return unix_datetime


def utc_to_unix_datetime(start_datetime):
    if start_datetime is None:
        unix_datetime = None
    else:
        # Adding date and time together in seconds
        formatted_start_datetime = start_datetime.split(".")[0].replace("T", " ")
        unix_datetime = convert_timezone_to_utc_epoch(formatted_start_datetime)
    return unix_datetime


def get_and_process_audit_logs(
    group_id, hostname, log, params, database_name, project_name
):
    gzip_results = doGZipGet(
        "cluster_logs",
        f"groups/{group_id}/clusters/{hostname}/logs/{log}",
        params=params,
    )

    results = str(gzip_results, "utf-8").splitlines()
    # Audit logs already come in JSON format
    json_results = convert_audit_logs_and_generate_id(
        results, hostname, database_name, project_name,
    )
    return json_results


def get_and_process_mongodb_logs(
    group_id, hostname, log, params, database_name, project_name
):
    gzip_results = doGZipGet(
        "cluster_logs",
        f"groups/{group_id}/clusters/{hostname}/logs/{log}",
        params=params,
    )

    log = ""
    i = 0
    while i < len(gzip_results):
        char = chr(gzip_results[i])
        log += char

        if char == "\n" and len(log) == 1:
            log = ""
        elif char == "\n":

            if log[-2:] == "{\n":
                new_line_counter = 0
                log = log[:-1] + " "
                while new_line_counter < 9:
                    i += 1
                    char = chr(gzip_results[i])
                    if char == "\n":
                        new_line_counter += 1
                        char = " "
                    log += char
                char = "\n"
                log += char

            log_test = " ".join(log.split())
            split_log_test = log_test.split(" ", 4)
            if len(split_log_test) == 4 and split_log_test[1] == "F":
                new_line_counter = 0
                log = log[:-1] + " "
                while new_line_counter < 2:
                    i += 1
                    char = chr(gzip_results[i])
                    if char == "\n":
                        new_line_counter += 1
                        char = " "
                    log += char
                char = "\n"
                log += char

            log_array = log.splitlines()
            converted_logs = convert_mongodb_logs_and_generate_id(
                log_array, hostname, database_name, project_name
            )
            yield converted_logs
            log = ""
        i += 1


def no_hwm_startdate():
    no_hwm_startdate_trigger.inc()
    current_datetime = datetime.now(tz=timezone.utc).isoformat()
    current_datetime_in_unix = utc_to_unix_datetime(current_datetime)
    one_hour_in_seconds = 3600
    # Time window will use environment variable, will default to one hour if not found.
    logs_time_window = int(environ.get("LOGS_TIME_WINDOW", one_hour_in_seconds))
    no_hwm_startdate = int(current_datetime_in_unix) - logs_time_window
    return no_hwm_startdate


def get_log_file(
    group_id,
    hostname,
    log,
    start_datetime_in_unix,
    end_datetime_in_unix,
    database_name,
    project_name,
):
    LOG_NAMES = [
        "mongodb.gz",
        "mongos.gz",
        "mongodb-audit-log.gz",
        "mongos-audit-log.gz",
    ]
    assert log in LOG_NAMES, "Invalid log name"
    params = None
    json_results = []

    if start_datetime_in_unix is None:
        current_datetime = datetime.now(tz=timezone.utc).isoformat()
        current_datetime_in_unix = utc_to_unix_datetime(current_datetime)
        startdate = no_hwm_startdate()
        params = {"startDate": startdate, "endDate": current_datetime_in_unix}

    else:
        params = {"startDate": start_datetime_in_unix, "endDate": end_datetime_in_unix}

    if "audit" in log:
        json_results = get_and_process_audit_logs(
            group_id, hostname, log, params, database_name, project_name
        )
    else:
        json_results = get_and_process_mongodb_logs(
            group_id, hostname, log, params, database_name, project_name
        )

    return json_results
