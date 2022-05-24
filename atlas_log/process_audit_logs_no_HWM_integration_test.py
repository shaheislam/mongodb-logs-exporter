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

    # Mocking the API request for the mongodb-audit logs
    mongodb_audit_log_response = '{"atype": "authenticate", "ts": {"$date": "2020-02-10T15:29:16.568+0000"}, "local": {"ip": "127.0.0.1", "port": 27017}, "remote": {"ip": "127.0.0.1", "port": 35430}, "users": [{"user": "mms-automation", "db": "admin"}], "roles": [{"role": "userAdminAnyDatabase", "db": "admin"}, {"role": "restore", "db": "admin"}, {"role": "backup", "db": "admin"}, {"role": "clusterAdmin", "db": "admin"}, {"role": "readWriteAnyDatabase", "db": "admin"}, {"role": "dbAdminAnyDatabase", "db": "admin"}], "param": {"user": "mms-automation", "db": "admin", "mechanism": "SCRAM-SHA-1"}, "result": 0}'
    compressed_response_mongodb_audit = gzip.compress(
        bytes(mongodb_audit_log_response, "utf-8")
    )
    requests_mock.register_uri(
        "GET",
        "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/clusters/hostname/logs/mongodb-audit-log.gz",
        content=compressed_response_mongodb_audit,
    )

    # Mocking the API request for the mongos-audit logs
    mongos_audit_log_response = ""
    compressed_response_mongos_audit = gzip.compress(
        bytes(mongos_audit_log_response, "utf-8")
    )
    requests_mock.register_uri(
        "GET",
        "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/clusters/hostname/logs/mongos-audit-log.gz",
        content=compressed_response_mongos_audit,
    )

    # Run the code
    get_latest.process_audit_log_files()

    # Getting the HWM from the mock bucket
    actual_HWM_audit_logs = (
        s3.Object(
            "test-bucket",
            "NdapAtlasLogs/cursors/log/my_group_hostname_mongodb-audit-log.gz.json",
        )
        .get()["Body"]
        .read()
    )
    expected_HWM_audit_logs = b'{"last_ids": ["5606903a3227f9a4badc901a107cd5c4cc2e9dbcad09731fbd724dcc1091b517"], "min_date": "2020-02-10T15:29:16.568+0000"}'
    assert actual_HWM_audit_logs == expected_HWM_audit_logs
