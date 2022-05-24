# pylint: disable=E1101

import pytest
import boto3
import json
import moto

from os import environ
from atlas_log import high_watermark


@pytest.fixture
def mock_config():
    environ["ATLAS_LOG_BUCKET"] = "my-bucket"
    environ["AWS_SECRET_ACCESS_KEY"] = "abcdefg"
    environ["AWS_ACCESS_KEY_ID"] = "my-access-key"


class TestGetWatermark:
    @moto.mock_s3
    def test_success(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        body = json.dumps({"min_date": "min_date", "last_ids": ["last_id"]})
        s3.Object("my-bucket", "my-watermark").put(Body=body)
        assert high_watermark.get_high_watermark("my-watermark") == {
            "min_date": "min_date",
            "last_ids": ["last_id"],
        }

    @moto.mock_s3
    def test_failure(self, mock_config):
        s3 = boto3.resource("s3")
        with pytest.raises(s3.meta.client.exceptions.NoSuchBucket):
            high_watermark.get_high_watermark("my-watermark")

    @moto.mock_s3
    def test_nosuchkey(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        assert high_watermark.get_high_watermark("my-watermark") == {
            "min_date": None,
            "last_ids": [],
        }


class TestNewHighWatermark:
    def test_success_single(self):
        assert high_watermark.new_high_watermark(
            [
                {"id": "1", "created": "1"},
                {"id": "3", "created": "3"},
                {"id": "2", "created": "2"},
            ]
        ) == {"last_ids": ["3"], "min_date": "3"}

    def test_success_multi(self):
        assert high_watermark.new_high_watermark(
            [
                {"id": "1", "created": "1"},
                {"id": "2", "created": "1"},
                {"id": "3", "created": "3"},
                {"id": "4", "created": "3"},
                {"id": "5", "created": "2"},
            ]
        ) == {"last_ids": ["3", "4"], "min_date": "3"}


class TestSetWatermark:
    @moto.mock_s3
    def test_success(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        high_watermark.set_high_watermark(
            "my-watermark", {"min_date": "123", "last_ids": ["id_1"]}
        )
        assert high_watermark.get_high_watermark("my-watermark") == {
            "min_date": "123",
            "last_ids": ["id_1"],
        }


class TestHighWatermarkFunctionality:
    @moto.mock_s3
    def test_totally_empty(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        data = []
        high_watermark.remove_last_ids(data, "my-watermark")
        assert data == []
        high_watermark.hwm_commit(data, "my-watermark")
        assert high_watermark.get_high_watermark("my-watermark") == {
            "min_date": None,
            "last_ids": [],
        }

    @moto.mock_s3
    def test_iterate_new(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        high_watermark.set_high_watermark(
            "my-watermark", {"min_date": "1", "last_ids": ["id_1"]}
        )

        data = [
            {"id": "id_3", "created": "3"},
            {"id": "id_2", "created": "2"},
            {"id": "id_1", "created": "1"},
        ]
        watermark = high_watermark.get_high_watermark("my-watermark")

        new_data = high_watermark.remove_last_ids(data, watermark)
        assert new_data == [
            {"id": "id_3", "created": "3"},
            {"id": "id_2", "created": "2"},
        ]
        high_watermark.hwm_commit(data, "my-watermark")
        assert high_watermark.get_high_watermark("my-watermark") == {
            "min_date": "3",
            "last_ids": ["id_3"],
        }

    @moto.mock_s3
    def test_iterate_multiple_ids(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        high_watermark.set_high_watermark(
            "my-watermark", {"min_date": "1", "last_ids": ["id_1", "id_2"]}
        )

        data = [
            {"id": "id_3", "created": "3"},
            {"id": "id_2", "created": "1"},
            {"id": "id_1", "created": "1"},
        ]
        watermark = high_watermark.get_high_watermark("my-watermark")

        new_data = high_watermark.remove_last_ids(data, watermark)
        assert new_data == [{"id": "id_3", "created": "3"}]
        high_watermark.hwm_commit(data, "my-watermark")

        assert high_watermark.get_high_watermark("my-watermark") == {
            "min_date": "3",
            "last_ids": ["id_3"],
        }

    @moto.mock_s3
    def test_dont_commit_by_mistake(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        high_watermark.set_high_watermark(
            "my-watermark", {"min_date": "1", "last_ids": ["id_1"]}
        )

        data = [
            {"id": "id_3", "created": "3"},
            {"id": "id_2", "created": "2"},
        ]
        watermark = high_watermark.get_high_watermark("my-watermark")

        new_data = high_watermark.remove_last_ids(data, watermark)
        assert new_data == data

        assert high_watermark.get_high_watermark("my-watermark") == {
            "min_date": "1",
            "last_ids": ["id_1"],
        }

    @moto.mock_s3
    def test_nothing_new(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        high_watermark.set_high_watermark(
            "my-watermark", {"min_date": "1", "last_ids": ["id_1"]}
        )

        data = [{"id": "id_1", "created": "1"}]
        watermark = high_watermark.get_high_watermark("my-watermark")

        new_data = high_watermark.remove_last_ids(data, watermark)
        assert new_data == []
        high_watermark.hwm_commit(data, "my-watermark")

        assert high_watermark.get_high_watermark("my-watermark") == {
            "min_date": "1",
            "last_ids": ["id_1"],
        }

    @moto.mock_s3
    def test_tolerates_out_of_order(self, mock_config):
        s3 = boto3.resource("s3")
        s3.create_bucket(Bucket="my-bucket")
        high_watermark.set_high_watermark(
            "my-watermark", {"min_date": "1", "last_ids": ["id_1", "id_2"]}
        )

        data = [
            {"id": "id_2", "created": "1"},
            {"id": "id_1", "created": "1"},
            {"id": "id_3", "created": "1"},
        ]
        watermark = high_watermark.get_high_watermark("my-watermark")

        new_data = high_watermark.remove_last_ids(data, watermark)
        assert new_data == [{"id": "id_3", "created": "1"}]
        high_watermark.hwm_commit(data, "my-watermark")

        assert high_watermark.get_high_watermark("my-watermark") == {
            "min_date": "1",
            "last_ids": ["id_2", "id_1", "id_3"],
        }
