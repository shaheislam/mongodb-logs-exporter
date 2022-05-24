"""
Glue the API and high-water mark features together to get the latest updates
"""
import logging
import time
from os import environ
from atlas_log import atlas_api, high_watermark, write_events
from datetime import datetime, timezone, timedelta
import requests
import botocore.exceptions
from prometheus_client import start_http_server, Counter, Enum, Summary, Gauge

# Metrics
uploaded_group_events = Counter(
    "atlas_log_exporter_uploaded_group_events",
    "The number of group events which have been uploaded",
    ["group"],
)
uploaded_org_events = Counter(
    "atlas_log_exporter_uploaded_org_events",
    "The number of org events which have been uploaded",
    ["org"],
)
uploaded_logs = Counter(
    "atlas_log_exporter_uploaded_logs",
    "The number of logs which have been uploaded",
    ["group", "cluster", "host", "log"],
)
uploaded_history = Counter(
    "atlas_log_exporter_uploaded_history",
    "The number of historical events which have been uploaded",
    ["group", "cluster"],
)

last_successful_upload = Gauge(
    "atlas_log_exporter_last_successful_upload",
    "Time of last successful upload of any type",
)

service_status = Enum(
    "atlas_log_exporter_status",
    "The status of the log exporter",
    states=[
        "sleeping",
        "processing_group_events",
        "processing_org_events",
        "processing_log_files",
        "processing_access_history",
    ],
)

log_exporter_s3_time = Summary(
    "atlas_log_exporter_s3_timer",
    "Times how long communication with s3 takes for events",
    ["log_type"],
)

exception_counter = Counter(
    "atlas_log_exporter_exception_counter",
    "Tracks the number of exceptions thrown by the code",
    ["exception_type"],
)


def update_last_successful_upload(array_length):
    if array_length > 0:
        last_successful_upload.set(int(round(time.time() * 1000)))


def events_to_s3(type_id, name, events, length, process, page_no, loop_count):
    with log_exporter_s3_time.labels(process).time():
        write_events.write_any_events(
            type_id, events, f"{loop_count}_{page_no}", process
        )
    if process == "group":
        uploaded_group_events.labels(name).inc(length)
    elif process == "org":
        uploaded_org_events.labels(name).inc(length)
    update_last_successful_upload(length)


def process_events_to_s3(
    type_id, name, gen, watermark_id, process, watermark, log_count, loop_count
):
    first_run = True
    page_no = 1
    for events in gen:
        filtered_events = events
        if first_run is True:
            if watermark and watermark["last_ids"]:
                filtered_events = high_watermark.remove_last_ids(events, watermark)

        length = len(events)

        events_to_s3(
            type_id, name, filtered_events, length, process, page_no, loop_count
        )

        if first_run is True:
            high_watermark.hwm_commit(events, watermark_id)
            first_run = False

        log_count += length
        page_no += 1
    return log_count


def process_org_events():
    orgs = atlas_api.get_orgs()
    percent_count = 1 / len(orgs) * 100
    percent_total = 0
    for org in orgs:
        try:
            org_id = org["id"]
            org_name = org["name"]
            logging.info("---------------------------------------------")
            logging.info("Started getting org events for %s", org_name)
            logging.info("---------------------------------------------")

            log_count = 0
            loop_count = 0
            start_datetime = None
            end_datetime = None
            current_datetime = datetime.now(tz=timezone.utc).isoformat()

            one_day_in_seconds = 86400
            org_events_time_window = int(
                environ.get("ORG_EVENTS_TIME_WINDOW", one_day_in_seconds)
            )

            data_from_mongo = True
            watermark_id = f"NdapAtlasLogs/cursors/orgs/{org_id}.json"
            watermark = high_watermark.get_high_watermark(watermark_id)
            start_datetime = watermark["min_date"]

            while data_from_mongo:

                if start_datetime is not None:
                    start_datetime_object = datetime.strptime(
                        start_datetime[:19], "%Y-%m-%dT%H:%M:%S"
                    )
                    end_datetime = (
                        start_datetime_object
                        + timedelta(seconds=org_events_time_window)
                    ).isoformat()

                gen = atlas_api.get_org_events(org_id, start_datetime, end_datetime)

                start_datetime = end_datetime

                log_count = process_events_to_s3(
                    org_id,
                    org_name,
                    gen,
                    watermark_id,
                    "org",
                    watermark,
                    log_count,
                    loop_count,
                )

                loop_count += 1

                if (start_datetime is None) or (start_datetime >= current_datetime):
                    data_from_mongo = False

            logging.info("---------------------------------------------")
            logging.info(
                "Retrieved %s events for org %s in %s pages",
                log_count,
                org_name,
                loop_count,
            )
            logging.info("---------------------------------------------")

            percent_total += percent_count
            logging.info("---------------------------------------------")
            logging.info(
                "Application %s percent through getting org events. Just finished %s",
                round(percent_total),
                org_name,
            )
            logging.info("---------------------------------------------")

        except requests.exceptions.HTTPError as e:
            exception_counter.labels("HTTP").inc()
            logging.error("Http request error: %s", e.response)
            continue
        except AssertionError as e:
            exception_counter.labels("Assertion").inc()
            logging.error("Encountered an error getting events for org %s: %s", org, e)
            continue
        except botocore.exceptions.ClientError as e:
            exception_counter.labels("s3").inc()
            logging.error("Unexpected error writing to s3: %s", e)
            continue
        except requests.exceptions.ChunkedEncodingError as e:
            exception_counter.labels("Chunking").inc()
            logging.error("Connection issue, retry: %s", e)
            continue
        except requests.exceptions.ConnectionError as e:
            exception_counter.labels("Connection").inc()
            logging.error("Connection error, retry: %s", e)
            continue


def process_group_events():
    groups = atlas_api.get_groups()
    percent_count = 1 / len(groups) * 100
    percent_total = 0
    for group in groups:
        try:
            group_id = group["id"]
            group_name = group["name"]
            logging.info("---------------------------------------------")
            logging.info("Started getting group events for %s", group_name)
            logging.info("---------------------------------------------")

            log_count = 0
            loop_count = 0
            start_datetime = None
            end_datetime = None
            current_datetime = datetime.now(tz=timezone.utc).isoformat()

            one_day_in_seconds = 86400
            group_events_time_window = int(
                environ.get("GROUP_EVENTS_TIME_WINDOW", one_day_in_seconds)
            )

            data_from_mongo = True
            watermark_id = f"NdapAtlasLogs/cursors/groups/{group_id}.json"
            watermark = high_watermark.get_high_watermark(watermark_id)
            start_datetime = watermark["min_date"]

            while data_from_mongo:

                if start_datetime is not None:
                    start_datetime_object = datetime.strptime(
                        start_datetime[:19], "%Y-%m-%dT%H:%M:%S"
                    )
                    end_datetime = (
                        start_datetime_object
                        + timedelta(seconds=group_events_time_window)
                    ).isoformat()

                gen = atlas_api.get_group_events(group_id, start_datetime, end_datetime)

                start_datetime = end_datetime

                log_count = process_events_to_s3(
                    group_id,
                    group_name,
                    gen,
                    watermark_id,
                    "group",
                    watermark,
                    log_count,
                    loop_count,
                )

                loop_count += 1

                if (start_datetime is None) or (start_datetime >= current_datetime):
                    data_from_mongo = False

            logging.info("---------------------------------------------")
            logging.info(
                "Retrieved %s events for group %s in %s pages",
                log_count,
                group_name,
                loop_count,
            )
            logging.info("---------------------------------------------")

            percent_total += percent_count
            logging.info("---------------------------------------------")
            logging.info(
                "Application %s percent through getting group events. Just finished %s",
                round(percent_total),
                group_name,
            )
            logging.info("---------------------------------------------")

        except requests.exceptions.HTTPError as e:
            exception_counter.labels("HTTP").inc()
            logging.error("Http request error: %s", e.response)
            continue
        except AssertionError as e:
            exception_counter.labels("Assertion").inc()
            logging.error(
                "Encountered an error getting events for group %s: %s", group, e
            )
            continue
        except botocore.exceptions.ClientError as e:
            exception_counter.labels("s3").inc()
            logging.error("Unexpected error writing to s3: %s", e)
            continue
        except requests.exceptions.ChunkedEncodingError as e:
            exception_counter.labels("Chunking").inc()
            logging.error("Connection issue, retry: %s", e)
            continue
        except requests.exceptions.ConnectionError as e:
            exception_counter.labels("Connection").inc()
            logging.error("Connection error, retry: %s", e)
            continue


def mongodb_logs_to_s3(
    group_id, hostname, log, loop_count, data, project_name, database_name, length
):
    logs_chunk_size = int(environ.get("MONGODB_LOGS_S3_CHUNK_SIZE", 1000))
    chunk_count = 0
    with log_exporter_s3_time.labels("log").time():
        for i in range(0, length, logs_chunk_size):
            write_events.write_logs(
                group_id,
                hostname,
                log,
                data[i : i + logs_chunk_size],
                loop_count,
                chunk_count,
            )
            chunk_count += 1
    uploaded_logs.labels(project_name, database_name, hostname, log).inc(length)
    update_last_successful_upload(length)


def process_mongodb_logs_to_s3(
    group_id,
    hostname,
    log,
    loop_count,
    gen,
    project_name,
    database_name,
    watermark,
    log_count,
    watermark_id,
):
    logs_array_counter = int(environ.get("MONGODB_LOGS_ARRAY_SIZE", 500))
    if logs_array_counter < len(watermark["last_ids"]):
        logs_array_counter = len(watermark["last_ids"])

    data_counter = 0
    logs_array = []
    first_run = True
    for data in gen:
        logs_array += data
        data_counter += 1
        if data_counter == logs_array_counter:
            filtered_logs_array = logs_array
            if first_run is True:
                if watermark and watermark["last_ids"]:
                    filtered_logs_array = high_watermark.remove_last_ids(
                        logs_array, watermark
                    )
                first_run = False

            length = len(logs_array)
            mongodb_logs_to_s3(
                group_id,
                hostname,
                log,
                loop_count,
                filtered_logs_array,
                project_name,
                database_name,
                length,
            )
            high_watermark.hwm_commit(logs_array, watermark_id)
            log_count += length
            logs_array = []
            data_counter = 0

    length = len(logs_array)
    mongodb_logs_to_s3(
        group_id,
        hostname,
        log,
        loop_count,
        logs_array,
        project_name,
        database_name,
        length,
    )
    high_watermark.hwm_commit(logs_array, watermark_id)
    log_count += length
    return log_count


def process_mongodb_log_files():
    LOG_NAMES = [
        "mongodb.gz",
        "mongos.gz",
    ]
    groups = atlas_api.get_groups()
    percent_count = 1 / len(groups) * 100
    percent_total = 0
    # Loops through returned arrays to send all possible log data
    for group in groups:
        project_name = group["name"]
        group_id = group["id"]
        clusters = atlas_api.get_clusters(group_id)
        for cluster in clusters:
            paused = cluster["paused"]
            database_name = cluster["name"]
            if paused is False:
                uri = cluster["mongoURI"].split(",")
                hostnames = atlas_api.uri_deconstruct(uri)
                if hostnames == []:
                    logging.warning("No hostnames found")
                for hostname in hostnames:
                    logging.info("---------------------------------------------")
                    logging.info("Started getting mongodb logs for %s", hostname)
                    logging.info("---------------------------------------------")

                    for log in LOG_NAMES:
                        try:
                            log_count = 0
                            loop_count = 0
                            start_datetime_in_unix = None
                            end_datetime_in_unix = None
                            current_datetime = datetime.now(tz=timezone.utc).isoformat()
                            current_datetime_in_unix = atlas_api.utc_to_unix_datetime(
                                current_datetime
                            )
                            one_day_in_seconds = 86400
                            logs_time_window = int(
                                environ.get(
                                    "MONGODB_LOGS_TIME_WINDOW", one_day_in_seconds
                                )
                            )

                            data_from_mongo = True
                            watermark_id = f"NdapAtlasLogs/cursors/log/{group_id}_{hostname}_{log}.json"
                            watermark = high_watermark.get_high_watermark(watermark_id)
                            start_datetime_in_unix = atlas_api.utc_to_unix_datetime(
                                watermark["min_date"]
                            )
                            while data_from_mongo:

                                if start_datetime_in_unix is not None:
                                    end_datetime_in_unix = (
                                        start_datetime_in_unix + logs_time_window
                                    )

                                gen = atlas_api.get_log_file(
                                    group_id,
                                    hostname,
                                    log,
                                    start_datetime_in_unix,
                                    end_datetime_in_unix,
                                    database_name,
                                    project_name,
                                )

                                start_datetime_in_unix = end_datetime_in_unix

                                log_count = process_mongodb_logs_to_s3(
                                    group_id,
                                    hostname,
                                    log,
                                    loop_count,
                                    gen,
                                    project_name,
                                    database_name,
                                    watermark,
                                    log_count,
                                    watermark_id,
                                )

                                loop_count += 1

                                if (start_datetime_in_unix is None) or (
                                    start_datetime_in_unix >= current_datetime_in_unix
                                ):
                                    data_from_mongo = False

                            logging.info(
                                "---------------------------------------------"
                            )
                            logging.info(
                                "Retrieved %s logs for log %s in hostname %s in group %s over %s loops",
                                log_count,
                                log,
                                hostname,
                                group_id,
                                loop_count,
                            )
                            logging.info(
                                "---------------------------------------------"
                            )

                        except requests.exceptions.HTTPError as e:
                            exception_counter.labels("HTTP").inc()
                            logging.error("Http request error: %s", e.response)
                            continue
                        except botocore.exceptions.ClientError as e:
                            exception_counter.labels("s3").inc()
                            logging.error("Unexpected error writing to s3: %s", e)
                            continue
                        except AssertionError as e:
                            exception_counter.labels("Assertion").inc()
                            logging.error("%s", e)
                            continue
                        except requests.exceptions.ChunkedEncodingError as e:
                            exception_counter.labels("Chunking").inc()
                            logging.error("Connection issue, retry: %s", e)
                            continue
                        except requests.exceptions.ConnectionError as e:
                            exception_counter.labels("Connection").inc()
                            logging.error("Connection error, retry: %s", e)
                            continue
            else:
                logging.info("---------------------------------------------")
                logging.info(
                    "Cluster %s is paused, cannot get logs from here", database_name
                )
                logging.info("---------------------------------------------")

        percent_total += percent_count
        logging.info("---------------------------------------------")
        logging.info(
            "Application %s percent through getting the mongodb logs. Just finished %s",
            round(percent_total),
            project_name,
        )
        logging.info("---------------------------------------------")


def audit_logs_to_s3(
    group_id, hostname, log, loop_count, data, project_name, database_name, length
):
    logs_chunk_size = int(environ.get("AUDIT_LOGS_S3_CHUNK_SIZE", 1000))
    chunk_count = 0
    with log_exporter_s3_time.labels("log").time():
        for i in range(0, length, logs_chunk_size):
            write_events.write_logs(
                group_id,
                hostname,
                log,
                data[i : i + logs_chunk_size],
                loop_count,
                chunk_count,
            )
            chunk_count += 1
    uploaded_logs.labels(project_name, database_name, hostname, log).inc(length)
    update_last_successful_upload(length)


def process_audit_logs_to_s3(
    group_id,
    hostname,
    log,
    loop_count,
    data,
    project_name,
    database_name,
    log_count,
    watermark_id,
    watermark,
):
    length = len(data)
    filtered_data = data
    if watermark and watermark["last_ids"]:
        filtered_data = high_watermark.remove_last_ids(data, watermark)
    audit_logs_to_s3(
        group_id,
        hostname,
        log,
        loop_count,
        filtered_data,
        project_name,
        database_name,
        length,
    )
    high_watermark.hwm_commit(data, watermark_id)
    log_count += length
    return log_count


def process_audit_log_files():
    LOG_NAMES = [
        "mongodb-audit-log.gz",
        "mongos-audit-log.gz",
    ]
    groups = atlas_api.get_groups()
    percent_count = 1 / len(groups) * 100
    percent_total = 0
    # Loops through returned arrays to send all possible log data
    for group in groups:
        project_name = group["name"]
        group_id = group["id"]
        clusters = atlas_api.get_clusters(group_id)
        for cluster in clusters:
            paused = cluster["paused"]
            database_name = cluster["name"]
            if paused is False:
                uri = cluster["mongoURI"].split(",")
                hostnames = atlas_api.uri_deconstruct(uri)
                if hostnames == []:
                    logging.warning("No hostnames found")
                for hostname in hostnames:
                    logging.info("---------------------------------------------")
                    logging.info("Started getting audit logs for %s", hostname)
                    logging.info("---------------------------------------------")

                    for log in LOG_NAMES:
                        try:
                            log_count = 0
                            loop_count = 0
                            start_datetime_in_unix = None
                            end_datetime_in_unix = None
                            current_datetime = datetime.now(tz=timezone.utc).isoformat()
                            current_datetime_in_unix = atlas_api.utc_to_unix_datetime(
                                current_datetime
                            )
                            one_day_in_seconds = 86400
                            logs_time_window = int(
                                environ.get(
                                    "AUDIT_LOGS_TIME_WINDOW", one_day_in_seconds
                                )
                            )

                            data_from_mongo = True
                            watermark_id = f"NdapAtlasLogs/cursors/log/{group_id}_{hostname}_{log}.json"
                            watermark = high_watermark.get_high_watermark(watermark_id)
                            start_datetime_in_unix = atlas_api.utc_to_unix_datetime(
                                watermark["min_date"]
                            )
                            while data_from_mongo:

                                if start_datetime_in_unix is not None:
                                    end_datetime_in_unix = (
                                        start_datetime_in_unix + logs_time_window
                                    )

                                logs_array = atlas_api.get_log_file(
                                    group_id,
                                    hostname,
                                    log,
                                    start_datetime_in_unix,
                                    end_datetime_in_unix,
                                    database_name,
                                    project_name,
                                )

                                start_datetime_in_unix = end_datetime_in_unix

                                log_count = process_audit_logs_to_s3(
                                    group_id,
                                    hostname,
                                    log,
                                    loop_count,
                                    logs_array,
                                    project_name,
                                    database_name,
                                    log_count,
                                    watermark_id,
                                    watermark,
                                )

                                loop_count += 1

                                if (start_datetime_in_unix is None) or (
                                    start_datetime_in_unix >= current_datetime_in_unix
                                ):
                                    data_from_mongo = False

                            logging.info(
                                "---------------------------------------------"
                            )
                            logging.info(
                                "Retrieved %s logs for log %s in hostname %s in group %s over %s loops",
                                log_count,
                                log,
                                hostname,
                                group_id,
                                loop_count,
                            )
                            logging.info(
                                "---------------------------------------------"
                            )

                        except requests.exceptions.HTTPError as e:
                            exception_counter.labels("HTTP").inc()
                            logging.error("Http request error: %s", e.response)
                            continue
                        except botocore.exceptions.ClientError as e:
                            exception_counter.labels("s3").inc()
                            logging.error("Unexpected error writing to s3: %s", e)
                            continue
                        except AssertionError as e:
                            exception_counter.labels("Assertion").inc()
                            logging.error("%s", e)
                            continue
                        except requests.exceptions.ChunkedEncodingError as e:
                            exception_counter.labels("Chunking").inc()
                            logging.error("Connection issue, retry: %s", e)
                            continue
                        except requests.exceptions.ConnectionError as e:
                            exception_counter.labels("Connection").inc()
                            logging.error("Connection error, retry: %s", e)
                            continue
            else:
                logging.info("---------------------------------------------")
                logging.info(
                    "Cluster %s is paused, cannot get logs from here", database_name
                )
                logging.info("---------------------------------------------")

        percent_total += percent_count
        logging.info("---------------------------------------------")
        logging.info(
            "Application %s percent through getting the audit logs. Just finished %s",
            round(percent_total),
            project_name,
        )
        logging.info("---------------------------------------------")


def access_history_to_s3(group_id, clustername, loop_count, data, project_name, length):
    access_history_chunk_size = int(environ.get("ACCESS_HISTORY_S3_CHUNK_SIZE", 1000))
    chunk_count = 0
    with log_exporter_s3_time.labels("history").time():
        for i in range(0, length, access_history_chunk_size):
            write_events.write_access_history(
                group_id,
                clustername,
                data[i : i + access_history_chunk_size],
                loop_count,
                chunk_count,
            )
            chunk_count += 1
    uploaded_history.labels(project_name, clustername).inc(length)
    update_last_successful_upload(length)


def process_access_history_to_s3(
    group_id,
    clustername,
    loop_count,
    data,
    project_name,
    watermark_id,
    log_count,
    watermark,
):
    length = len(data)
    filtered_data = data
    if watermark and watermark["last_ids"]:
        filtered_data = high_watermark.remove_last_ids(data, watermark)
    access_history_to_s3(
        group_id, clustername, loop_count, filtered_data, project_name, length
    )
    high_watermark.hwm_commit(data, watermark_id)
    log_count += length
    return log_count


def process_access_history_events():
    groups = atlas_api.get_groups()
    percent_count = 1 / len(groups) * 100
    percent_total = 0
    for group in groups:
        group_id = group["id"]
        project_name = group["name"]
        clusters = atlas_api.get_clusters(group_id)
        for cluster in clusters:
            paused = cluster["paused"]
            clustername = cluster["name"]
            logging.info("---------------------------------------------")
            logging.info(
                "Started getting access history for %s, cluster %s",
                project_name,
                clustername,
            )
            logging.info("---------------------------------------------")

            if paused is False:
                try:
                    log_count = 0
                    loop_count = 0
                    start_datetime_in_unix_milliseconds = None
                    end_datetime_in_unix_milliseconds = None
                    current_datetime = datetime.now(tz=timezone.utc).isoformat()
                    current_datetime_in_unix_milliseconds = atlas_api.utc_to_unix_milliseconds_datetime(
                        current_datetime
                    )
                    thirty_days_in_milliseconds = 86400000 * 30
                    access_history_time_window = int(
                        environ.get(
                            "ACCESS_HISTORY_TIME_WINDOW", thirty_days_in_milliseconds
                        )
                    )

                    data_from_mongo = True
                    watermark_id = (
                        f"NdapAtlasLogs/cursors/access-history/{clustername}.json"
                    )
                    watermark = high_watermark.get_high_watermark(watermark_id)
                    start_datetime_in_unix_milliseconds = atlas_api.utc_to_unix_milliseconds_datetime(
                        watermark["min_date"]
                    )
                    while data_from_mongo:

                        if start_datetime_in_unix_milliseconds is not None:
                            end_datetime_in_unix_milliseconds = (
                                start_datetime_in_unix_milliseconds
                                + access_history_time_window
                            )

                        data = atlas_api.get_access_logs(
                            group_id,
                            clustername,
                            start_datetime_in_unix_milliseconds,
                            end_datetime_in_unix_milliseconds,
                            project_name,
                        )

                        start_datetime_in_unix_milliseconds = (
                            end_datetime_in_unix_milliseconds
                        )

                        log_count = process_access_history_to_s3(
                            group_id,
                            clustername,
                            loop_count,
                            data,
                            project_name,
                            watermark_id,
                            log_count,
                            watermark,
                        )

                        loop_count += 1

                        if (start_datetime_in_unix_milliseconds is None) or (
                            start_datetime_in_unix_milliseconds
                            >= current_datetime_in_unix_milliseconds
                        ):
                            data_from_mongo = False

                    logging.info("---------------------------------------------")
                    logging.info(
                        "Retrieved %s database access logs for clustername %s in group %s",
                        log_count,
                        clustername,
                        group_id,
                    )
                    logging.info("---------------------------------------------")

                except requests.exceptions.HTTPError as e:
                    exception_counter.labels("HTTP").inc()
                    logging.error("Http request error: %s", e.response)
                    continue
                except botocore.exceptions.ClientError as e:
                    exception_counter.labels("s3").inc()
                    logging.error("Unexpected error writing to s3: %s", e)
                    continue
                except AssertionError as e:
                    exception_counter.labels("Assertion").inc()
                    logging.error("%s", e)
                    continue
                except requests.exceptions.ChunkedEncodingError as e:
                    exception_counter.labels("Chunking").inc()
                    logging.error("Chunking issue, retry: %s", e)
                    continue
                except requests.exceptions.ConnectionError as e:
                    exception_counter.labels("Connection").inc()
                    logging.error("Connection error, retry: %s", e)
                    continue
            else:
                logging.info("---------------------------------------------")
                logging.info(
                    "Cluster %s is paused, cannot get logs from here", clustername
                )
                logging.info("---------------------------------------------")

        percent_total += percent_count
        logging.info("---------------------------------------------")

        logging.info(
            "Application %s percent through getting the access history events. Just finished %s",
            round(percent_total),
            project_name,
        )
        logging.info("---------------------------------------------")


# Entry Point to the script
# Suggestions
# 1. Run as a simple program that puts stuff to S3
# 2. Run a Simple HTTP Server which does the above and too provides health
if __name__ == "__main__":  # pragma: no cover
    log_level = logging.getLevelName(environ.get("LOG_LEVEL", logging.INFO))
    logging.basicConfig(level=log_level)
    sleep_secs = int(environ.get("SLEEP_SECS", "60"))
    start_http_server(8000)

    while True:
        service_status.state("processing_group_events")
        process_group_events()
        logging.info("---------------------------------------------")
        logging.info("Done getting group events")
        logging.info("---------------------------------------------")

        service_status.state("processing_org_events")
        process_org_events()
        logging.info("---------------------------------------------")
        logging.info("Done getting org events")
        logging.info("---------------------------------------------")

        service_status.state("processing_log_files")
        process_mongodb_log_files()
        logging.info("---------------------------------------------")
        logging.info("Done getting mongodb logs")
        logging.info("---------------------------------------------")

        process_audit_log_files()
        logging.info("---------------------------------------------")
        logging.info("Done getting audit logs")
        logging.info("---------------------------------------------")

        service_status.state("processing_access_history")
        process_access_history_events()
        logging.info("---------------------------------------------")
        logging.info("Done access history logs")
        logging.info("---------------------------------------------")

        logging.info("---------------------------------------------")
        logging.info("Finished current poll, waiting for %s seconds", sleep_secs)
        logging.info("---------------------------------------------")

        service_status.state("sleeping")
        # This is setting the poll delay
        time.sleep(sleep_secs)
