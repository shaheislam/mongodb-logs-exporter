# pylint: disable=E1101

import pytest
from os import environ
import moto
import boto3
from datetime import datetime, timezone
from freezegun import freeze_time

from atlas_log import write_events


@pytest.fixture
def mock_config():
    environ["ATLAS_LOG_BUCKET"] = "my-bucket"
    environ["AWS_SECRET_ACCESS_KEY"] = "abcdefg"
    environ["AWS_ACCESS_KEY_ID"] = "my-access-key"


class TestWriteGroupEventsLogs:
    @moto.mock_s3
    # Stop the clock and set it to a certain value
    # Provides an arbritrary time to assert on
    @freeze_time(datetime.fromtimestamp(1234.56, timezone.utc))
    def test_always_includes_heartbeat(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        write_events.write_logs("group", "hostname", "folder", [], 1, 1)
        actual = (
            s3.Object(
                "my-bucket",
                "NdapAtlasLogs/logs/folder/group_hostname_page_1_chunk_1_1234.log",
            )
            .get()["Body"]
            .read()
        )
        expected = b'{"created": "1970-01-01T00:20:34.560000+00:00", "eventTypeName": "@ATLAS_LOG_TO_S3_HEARTBEAT"}\n'
        assert actual == expected

    @moto.mock_s3
    @freeze_time(datetime.fromtimestamp(1234.56, timezone.utc))
    def test_multiple(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        write_events.write_logs(
            "group", "hostname", "folder", [{"id": "ev_1"}, {"id": "ev_2"}], 1, 1
        )
        actual = (
            s3.Object(
                "my-bucket",
                f"NdapAtlasLogs/logs/folder/group_hostname_page_1_chunk_1_1234.log",
            )
            .get()["Body"]
            .read()
        )
        expected = b'{"id": "ev_1"}\n{"id": "ev_2"}\n{"created": "1970-01-01T00:20:34.560000+00:00", "eventTypeName": "@ATLAS_LOG_TO_S3_HEARTBEAT"}\n'
        assert actual == expected


class TestWriteGroupEvents:
    @moto.mock_s3
    # Stop the clock and set it to a certain value
    # Provides an arbritrary time to assert on
    @freeze_time(datetime.fromtimestamp(1234.56, timezone.utc))
    def test_always_includes_heartbeat(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        write_events.write_any_events("my-group", [], 1, "group")
        actual = (
            s3.Object(
                "my-bucket", f"NdapAtlasLogs/logs/groups/my-group_pageno_1_1234.log"
            )
            .get()["Body"]
            .read()
        )
        expected = b'{"created": "1970-01-01T00:20:34.560000+00:00", "eventTypeName": "@ATLAS_LOG_TO_S3_HEARTBEAT"}\n'
        assert actual == expected

    @moto.mock_s3
    @freeze_time(datetime.fromtimestamp(1234.56, timezone.utc))
    def test_multiple(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        write_events.write_any_events(
            "my-group", [{"id": "ev_1"}, {"id": "ev_2"}], 1, "group"
        )
        actual = (
            s3.Object(
                "my-bucket", f"NdapAtlasLogs/logs/groups/my-group_pageno_1_1234.log"
            )
            .get()["Body"]
            .read()
        )
        expected = b'{"id": "ev_1"}\n{"id": "ev_2"}\n{"created": "1970-01-01T00:20:34.560000+00:00", "eventTypeName": "@ATLAS_LOG_TO_S3_HEARTBEAT"}\n'
        assert actual == expected


class TestWriteAccessEvents:
    @moto.mock_s3
    # Stop the clock and set it to a certain value
    # Provides an arbritrary time to assert on
    @freeze_time(datetime.fromtimestamp(1234.56, timezone.utc))
    def test_always_includes_heartbeat(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        write_events.write_access_history("my-group", "my-clustername", [], 1, 1)
        actual = (
            s3.Object(
                "my-bucket",
                f"NdapAtlasLogs/logs/access-history/my-group_clusternames_my-clustername_page_1_chunk_1_1234.log",
            )
            .get()["Body"]
            .read()
        )
        expected = b'{"created": "1970-01-01T00:20:34.560000+00:00", "eventTypeName": "@ATLAS_LOG_TO_S3_HEARTBEAT"}\n'
        assert actual == expected

    @moto.mock_s3
    @freeze_time(datetime.fromtimestamp(1234.56, timezone.utc))
    def test_multiple(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        write_events.write_access_history(
            "my-group", "my-clustername", [{"id": "ev_1"}, {"id": "ev_2"}], 1, 1
        )
        actual = (
            s3.Object(
                "my-bucket",
                f"NdapAtlasLogs/logs/access-history/my-group_clusternames_my-clustername_page_1_chunk_1_1234.log",
            )
            .get()["Body"]
            .read()
        )
        expected = b'{"id": "ev_1"}\n{"id": "ev_2"}\n{"created": "1970-01-01T00:20:34.560000+00:00", "eventTypeName": "@ATLAS_LOG_TO_S3_HEARTBEAT"}\n'
        assert actual == expected


class TestWriteOrgEvents:
    @moto.mock_s3
    @freeze_time(datetime.fromtimestamp(1234.56, timezone.utc))
    def test_always_includes_heartbeat(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        write_events.write_any_events("my-org", [], 1, "org")
        actual = (
            s3.Object("my-bucket", f"NdapAtlasLogs/logs/orgs/my-org_pageno_1_1234.log")
            .get()["Body"]
            .read()
        )
        expected = b'{"created": "1970-01-01T00:20:34.560000+00:00", "eventTypeName": "@ATLAS_LOG_TO_S3_HEARTBEAT"}\n'
        assert actual == expected

    @moto.mock_s3
    @freeze_time(datetime.fromtimestamp(1234.56, timezone.utc))
    def test_multiple(
        self, mock_config,
    ):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        write_events.write_any_events(
            "my-org", [{"id": "ev_1"}, {"id": "ev_2"}], 1, "org"
        )
        actual = (
            s3.Object("my-bucket", f"NdapAtlasLogs/logs/orgs/my-org_pageno_1_1234.log")
            .get()["Body"]
            .read()
        )
        expected = b'{"id": "ev_1"}\n{"id": "ev_2"}\n{"created": "1970-01-01T00:20:34.560000+00:00", "eventTypeName": "@ATLAS_LOG_TO_S3_HEARTBEAT"}\n'
        assert actual == expected
