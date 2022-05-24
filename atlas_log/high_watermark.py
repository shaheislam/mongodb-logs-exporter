# pylint: disable=E1101

"""
Turns Atlas APIs into pollable data streams by using the last retrieved item as a high-water mark.
"""
import logging
import json
import boto3
from os import environ


def get_high_watermark(object_key):
    s3 = boto3.resource("s3")
    try:
        obj = s3.Object(environ["ATLAS_LOG_BUCKET"], object_key).get()
        result = json.loads(obj["Body"].read())
        logging.info(
            "Retrieved high-water mark %s", result,
        )
        return result
    except s3.meta.client.exceptions.NoSuchKey:
        logging.debug(
            "High-water mark for %s in %s was missing: Presumably this is the first run",
            object_key,
            environ["ATLAS_LOG_BUCKET"],
        )
    return {
        "min_date": None,
        "last_ids": [],
    }


def set_high_watermark(object_key, hwm):
    assert hwm["min_date"]
    assert hwm["last_ids"]
    s3 = boto3.resource("s3")
    body = json.dumps(hwm)
    s3.Object(environ["ATLAS_LOG_BUCKET"], object_key).put(Body=body)
    logging.info(
        "Updated high-water mark %s", body,
    )


def new_high_watermark(results):
    max_created = max(results, key=lambda result: result["created"])["created"]
    latest_results = filter(lambda result: result["created"] == max_created, results)
    latest_ids = list(map(lambda result: result["id"], latest_results))
    return {"last_ids": latest_ids, "min_date": max_created}


def remove_last_ids(events, watermark):
    "Remove the IDs we found in the previous watermark"
    results = list(
        filter(
            lambda result: (result["id"] not in watermark["last_ids"])
            and (result["created"] >= watermark["min_date"]),
            events,
        )
    )
    return results


def hwm_commit(data, watermark_id):
    if data:
        hwm = new_high_watermark(data)
        set_high_watermark(watermark_id, hwm)
