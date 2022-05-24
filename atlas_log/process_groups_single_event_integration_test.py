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
@freeze_time(datetime.fromtimestamp(1234, timezone.utc))
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
    s3.Object("test-bucket", "NdapAtlasLogs/cursors/groups/my_group.json").put(
        Body=mock_watermark
    )

    # Mocking the API request for the group events
    get_group_events_response = json.dumps(
        {
            "results": [
                {
                    "apiKeyId": "my_api_key_id",
                    "created": "2020-02-07T00:20:34.560000+00:00",
                    "eventTypeName": "MONGODB_LOGS_DOWNLOADED",
                    "groupId": "my_group",
                    "id": "my_event_id",
                    "isGlobalAdmin": "false",
                    "links": [
                        {
                            "href": "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events/my_event_id",
                            "rel": "self",
                        }
                    ],
                    "publicKey": "my_public_key",
                    "remoteAddress": "my_remote_address",
                }
            ]
        }
    )
    requests_mock.register_uri(
        "GET",
        "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?minDate=2020-02-06T11%3A02%3A35.297%2B0000&itemsPerPage=500&pageNum=1&maxDate=2020-02-07T11%3A02%3A35",
        text=get_group_events_response,
    )

    # Run the code
    get_latest.process_group_events()

    # Getting the HWM from the mock bucket
    actual_HWM = (
        s3.Object("test-bucket", "NdapAtlasLogs/cursors/groups/my_group.json")
        .get()["Body"]
        .read()
    )

    # Make assertions
    expected_HWM = (
        b'{"last_ids": ["my_event_id"], "min_date": "2020-02-07T00:20:34.560000+00:00"}'
    )
    assert actual_HWM == expected_HWM

    actual_group_events = (
        s3.Object(
            "test-bucket", "NdapAtlasLogs/logs/groups/my_group_pageno_0_1_1234.log"
        )
        .get()["Body"]
        .read()
    )
    expected_group_events = (
        b'{"apiKeyId": "my_api_key_id", "created": "2020-02-07T00:20:34.560000+00:00",'
        b' "eventTypeName": "MONGODB_LOGS_DOWNLOADED", "groupId": "my_group", "id": "m'
        b'y_event_id", "isGlobalAdmin": "false", "links": [{"href": "https://cloud.mon'
        b'godb.com/api/atlas/v1.0/groups/my_group/events/my_event_id", "rel": "self"}]'
        b', "publicKey": "my_public_key", "remoteAddress": "my_remote_address"}\n{"'
        b'created": "1970-01-01T00:20:34+00:00", "eventTypeName": "@ATLAS_LOG_TO_S3_HE'
        b'ARTBEAT"}\n'
    )
    assert actual_group_events == expected_group_events
