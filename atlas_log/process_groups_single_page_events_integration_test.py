# pylint: disable=E1101

import pytest
from os import environ
from requests.auth import HTTPDigestAuth
import json
from datetime import datetime, timezone
import boto3
import moto
from freezegun import freeze_time
from atlas_log import get_latest


@pytest.fixture
def mock_config():
    environ["ATLAS_USERNAME"] = "jond3k@gmail.com"
    environ["ATLAS_APIKEY"] = "a_fake_api_key"

    environ["ATLAS_LOG_BUCKET"] = "test-bucket"
    environ["AWS_SECRET_ACCESS_KEY"] = "abcdefg"
    environ["AWS_ACCESS_KEY_ID"] = "my-access-key"


def mk_auth():
    return HTTPDigestAuth(environ["ATLAS_USERNAME"], environ["ATLAS_APIKEY"])


@moto.mock_s3
@freeze_time(datetime.fromtimestamp(2345, timezone.utc))
def test_process_group_events_with_no_HWM(requests_mock, mock_config):

    # Mocking the API request for the groups
    get_all_groups_response = json.dumps(
        {"results": [{"id": "my_group", "name": "foo"}]}
    )
    requests_mock.register_uri(
        "GET",
        "https://cloud.mongodb.com/api/atlas/v1.0/groups",
        text=get_all_groups_response,
    )

    # Writing the HWM to the mock bucket
    s3 = boto3.resource("s3")
    s3.create_bucket(Bucket="test-bucket")
    mock_watermark = json.dumps(
        {
            "last_ids": [
                "888371595ee58785a0def41a266b96ab77859ba0072788f64b41d43a070063e8"
            ],
            "min_date": "2020-02-06T11:02:35.297+0000",
        }
    )
    s3.Object("test-bucket", "NdapAtlasLogs/cursors/groups/my_watermark").put(
        Body=mock_watermark
    )

    # Mocking the API request for the group events

    get_group_events_response = json.dumps(
        {
            "results": [
                {
                    "created": "'2020-02-12T00:13:9." + str(i / 50) + ".560000+00:00'",
                    "id": str(i),
                }
                for i in range(0, 500)
            ]
        }
    )

    requests_mock.register_uri(
        "GET",
        "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?itemsPerPage=500&pageNum=1",
        text=get_group_events_response,
    )

    get_group_events_response2 = json.dumps({"results": []})

    requests_mock.register_uri(
        "GET",
        "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?itemsPerPage=500&pageNum=2",
        text=get_group_events_response2,
    )

    # Run the code
    get_latest.process_group_events()

    # Getting the HWM from the mock bucket
    actual_HWM = (
        s3.Object("test-bucket", "NdapAtlasLogs/cursors/groups/my_watermark")
        .get()["Body"]
        .read()
    )

    # Make assertions
    expected_HWM = b'{"last_ids": ["888371595ee58785a0def41a266b96ab77859ba0072788f64b41d43a070063e8"], "min_date": "2020-02-06T11:02:35.297+0000"}'
    assert actual_HWM == expected_HWM

    actual_group_events = (
        s3.Object(
            "test-bucket", "NdapAtlasLogs/logs/groups/my_group_pageno_0_1_2345.log"
        )
        .get()["Body"]
        .read()
    )

    expected_group_events = b""
    for i in range(0, 500):
        expected_group_events += (
            b'{"created": "\'2020-02-12T00:13:9.'
            + str(i / 50).encode()
            + b".560000+00:00'\", "
            b'"id": "' + str(i).encode() + b'"}\n'
        )

    expected_group_events += b'{"created": "1970-01-01T00:39:05+00:00", "eventTypeName": "@ATLAS_LOG_TO_S3_HEARTBEAT"}\n'
    assert actual_group_events == expected_group_events
