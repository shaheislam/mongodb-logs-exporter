# pylint: disable=E1101

import pytest
from os import environ
from requests.auth import HTTPDigestAuth
import json
import gzip
import boto3
import moto
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
# @freeze_time(datetime.fromtimestamp(1234.56, timezone.utc))
def test_process_log_events_with_no_HWM(requests_mock, mock_config):

    # Mocking the API request for the groups
    get_all_groups_response = json.dumps(
        {"results": [{"id": "my_group", "name": "project_name"}]}
    )
    requests_mock.register_uri(
        "GET",
        "https://cloud.mongodb.com/api/atlas/v1.0/groups",
        text=get_all_groups_response,
    )

    # Mocking the API request for the clusters
    get_all_clusters_response = json.dumps(
        {
            "results": [
                {
                    "mongoURI": "mongodb://hostname:27017",
                    "name": "database_name",
                    "paused": False,
                }
            ]
        }
    )
    requests_mock.register_uri(
        "GET",
        "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/clusters",
        text=get_all_clusters_response,
    )

    # Setting up mock s3 bucket
    s3 = boto3.resource("s3")
    s3.create_bucket(Bucket="test-bucket")

    # Mocking the API request for the mongodb logs
    mongodb_log_response = "2020-01-30T14:48:24.037+0000 I NETWORK  [conn373449] end connection 192.168.254.244:54430 (25 connections now open)\n"
    compressed_response_mongodb = gzip.compress(bytes(mongodb_log_response, "utf-8"))
    requests_mock.register_uri(
        "GET",
        "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/clusters/hostname/logs/mongodb.gz",
        content=compressed_response_mongodb,
    )

    # Mocking the API request for the mongos logs
    mongos_log_response = ""
    compressed_response_mongos = gzip.compress(bytes(mongos_log_response, "utf-8"))
    requests_mock.register_uri(
        "GET",
        "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/clusters/hostname/logs/mongos.gz",
        content=compressed_response_mongos,
    )

    # Run the code
    get_latest.process_mongodb_log_files()

    # Getting the HWM from the mock bucket
    actual_HWM_mongodb_logs = (
        s3.Object(
            "test-bucket", "NdapAtlasLogs/cursors/log/my_group_hostname_mongodb.gz.json"
        )
        .get()["Body"]
        .read()
    )
    expected_HWM_mongodb_logs = b'{"last_ids": ["c381467dfcd768ed19f0c30c178793be691321537a902019fe354b50c8160c05"], "min_date": "2020-01-30T14:48:24.037+0000"}'
    assert actual_HWM_mongodb_logs == expected_HWM_mongodb_logs
