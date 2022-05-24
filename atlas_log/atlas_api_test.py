import pytest
import json
from os import environ
import gzip
from freezegun import freeze_time
from datetime import datetime, timezone

from atlas_log import atlas_api


@pytest.fixture
def mock_config():
    environ["ATLAS_USERNAME"] = "jond3k@gmail.com"
    environ["ATLAS_APIKEY"] = "a_fake_api_key"


@pytest.fixture
def mock_config_no_hwm():
    environ["LOGS_TIME_WINDOW"] = "1000"


@pytest.fixture
def mock_config_no_hwm_get_log_file():
    environ["ATLAS_USERNAME"] = "jond3k@gmail.com"
    environ["ATLAS_APIKEY"] = "a_fake_api_key"
    environ["LOGS_TIME_WINDOW"] = "1000"


def test_utc_to_unix_date():
    expected = "2020-01-29T16:24:02.123+0000"
    assert atlas_api.utc_to_unix_datetime(expected) == 1580315042

    expected_daylight_saving = "2010-08-10T08:07:24.000+0000"
    assert atlas_api.utc_to_unix_datetime(expected_daylight_saving) == 1281427644

    expected_random_time = "1973-11-29T21:33:09.000+0000"
    assert atlas_api.utc_to_unix_datetime(expected_random_time) == 123456789

    expected_different_timezone = "1973-11-29T21:33:09.000+0200"
    assert atlas_api.utc_to_unix_datetime(expected_different_timezone) == 123456789

    expected_none = None
    assert atlas_api.utc_to_unix_datetime(expected_none) == None


def test_get_clusters(requests_mock, mock_config):
    expected = json.dumps({"results": [{"id": "123"}]})
    requests_mock.register_uri(
        "GET",
        "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/clusters",
        text=expected,
    )
    assert atlas_api.get_clusters("my_group") == [{"id": "123"}]


def test_get_groups(requests_mock, mock_config):
    expected = json.dumps({"results": [{"id": "123"}]})
    requests_mock.register_uri(
        "GET", "https://cloud.mongodb.com/api/atlas/v1.0/groups", text=expected
    )
    assert atlas_api.get_groups() == [{"id": "123"}]


def test_get_orgs(requests_mock, mock_config):
    expected = json.dumps({"results": [{"id": "123"}]})
    requests_mock.register_uri(
        "GET", "https://cloud.mongodb.com/api/atlas/v1.0/orgs", text=expected
    )
    assert atlas_api.get_orgs() == [{"id": "123"}]


def test_convert_mongodb_logs_and_generate_id():
    expected = [
        {
            "id": "55e6f31582c2870057ab4416947d2fee018962e7bc956b702a1553b7b8545e4b",
            "hostname": "shard_name",
            "created": "2020-01-27T08:32:28.894+0000",
            "severity": "I",
            "component": "NETWORK",
            "context": "listener",
            "message": "connection accepted from 192.168.254.244:59506 #329772 (26 connections now open)",
            "database": "database_name",
            "project": "project_name",
        }
    ]
    json_logs = atlas_api.convert_mongodb_logs_and_generate_id(
        [
            "2020-01-27T08:32:28.894+0000 I NETWORK  [listener] connection accepted from 192.168.254.244:59506 #329772 (26 connections now open)",
        ],
        "shard_name",
        "database_name",
        "project_name",
    )

    assert json_logs == expected


def test_convert_mongodb_logs_and_generate_id_worst_case():
    expected = [
        {
            "component": "CONTROL",
            "hostname": "shard_name",
            "context": "conn282969",
            "created": "2020-02-27T19:54:29.032+0000",
            "id": "5c8fe22bcb5b805265372f31ec3d51bbd7e9b7f03d7d3fd9e3c61d861d664f34",
            "message": ""
            'options: { auditLog: { destination: "file", filter: '
            '"{ "$or": [ { "users": [] }, { "$and": [ { "$or": [ { "users": { '
            '...", format: "JSON", path: '
            '"/srv/mongodb/izumi-test-shard-0-node-0/auditLog.json" }, '
            "config: "
            '"/srv/mongodb/izumi-test-shard-0-node-0/automation-mongod.conf", '
            'net: { bindIp: "0.0.0.0", compression: { compressors: '
            '"snappy,zlib" }, maxIncomingConnections: 750, '
            'maxIncomingConnectionsOverride: [ "192.168.248.0/21" ], port: '
            '27017, ssl: { CAFile: "/etc/pki/tls/certs/atlas-bundle.crt", '
            'PEMKeyFile: "/etc/pki/tls/private/mongod.pem", '
            "allowConnectionsWithoutCertificates: true, clusterCAFile: "
            '"/var/lib/mongodb-mms-automation/atlas-cluster-managed.crt", '
            'disabledProtocols: "TLS1_0", mode: "requireSSL" } }, '
            "processManagement: { fork: true }, replication: { replSetName: "
            '"izumi-test-shard-0" }, security: { authorization: "enabled", '
            "javascriptEnabled: true, keyFile: "
            '"/var/lib/mongodb-mms-automation/keyfile" }, setParameter: { '
            'allowRolesFromX509Certificates: "false", '
            'auditAuthorizationSuccess: "false", authenticationMechanisms: '
            '"SCRAM-SHA-1,MONGODB-X509", failIndexKeyTooLong: "true", '
            'honorSystemUmask: "false", maxIndexBuildMemoryUsageMegabytes: '
            '"100", notablescan: "false", '
            'reportOpWriteConcernCountersInServerStatus: "true", '
            'sslWithholdClientCertificate: "true", '
            'suppressNoTLSPeerCertificateWarning: "true", ttlMonitorEnabled: '
            '"true", watchdogPeriodSeconds: "60" }, storage: { dbPath: '
            '"/srv/mongodb/izumi-test-shard-0-node-0", engine: "wiredTiger", '
            'wiredTiger: { engineConfig: { configString: "cache_size=512MB" } '
            '} }, systemLog: { destination: "file", logAppend: true, path: '
            '"/srv/mongodb/izumi-test-shard-0-node-0/mongodb.log" } }',
            "severity": "I",
            "database": "database_name",
            "project": "project_name",
        }
    ]
    json_logs = atlas_api.convert_mongodb_logs_and_generate_id(
        [
            '2020-02-27T19:54:29.032+0000 I CONTROL  [conn282969] options: { auditLog: { destination: "file", filter: "{\n  "$or": [\n    {\n      "users": []\n    },\n    {\n      "$and": [\n        {\n          "$or": [\n            {\n              "users": {\n                ...", format: "JSON", path: "/srv/mongodb/izumi-test-shard-0-node-0/auditLog.json" }, config: "/srv/mongodb/izumi-test-shard-0-node-0/automation-mongod.conf", net: { bindIp: "0.0.0.0", compression: { compressors: "snappy,zlib" }, maxIncomingConnections: 750, maxIncomingConnectionsOverride: [ "192.168.248.0/21" ], port: 27017, ssl: { CAFile: "/etc/pki/tls/certs/atlas-bundle.crt", PEMKeyFile: "/etc/pki/tls/private/mongod.pem", allowConnectionsWithoutCertificates: true, clusterCAFile: "/var/lib/mongodb-mms-automation/atlas-cluster-managed.crt", disabledProtocols: "TLS1_0", mode: "requireSSL" } }, processManagement: { fork: true }, replication: { replSetName: "izumi-test-shard-0" }, security: { authorization: "enabled", javascriptEnabled: true, keyFile: "/var/lib/mongodb-mms-automation/keyfile" }, setParameter: { allowRolesFromX509Certificates: "false", auditAuthorizationSuccess: "false", authenticationMechanisms: "SCRAM-SHA-1,MONGODB-X509", failIndexKeyTooLong: "true", honorSystemUmask: "false", maxIndexBuildMemoryUsageMegabytes: "100", notablescan: "false", reportOpWriteConcernCountersInServerStatus: "true", sslWithholdClientCertificate: "true", suppressNoTLSPeerCertificateWarning: "true", ttlMonitorEnabled: "true", watchdogPeriodSeconds: "60" }, storage: { dbPath: "/srv/mongodb/izumi-test-shard-0-node-0", engine: "wiredTiger", wiredTiger: { engineConfig: { configString: "cache_size=512MB" } } }, systemLog: { destination: "file", logAppend: true, path: "/srv/mongodb/izumi-test-shard-0-node-0/mongodb.log" } }\n'
        ],
        "shard_name",
        "database_name",
        "project_name",
    )

    assert json_logs == expected


def test_convert_convert_audit_logs_and_generate_id():
    expected = [
        {
            "id": "6e3f6801eee3be91dc93dfa6745322517607da8977875c9c94e189d3e1d72c26",
            "hostname": "shard_name",
            "created": "2020-01-30T16:02:59.770+0000",
            "audit_dump": {
                "atype": "authenticate",
                "ts": {"$date": "2020-01-30T16:02:59.770+0000"},
                "local": {"ip": "127.0.0.1", "port": 27017},
                "remote": {"ip": "127.0.0.1", "port": 60406},
                "users": [{"user": "mms-automation", "db": "admin"}],
                "roles": [
                    {"role": "userAdminAnyDatabase", "db": "admin"},
                    {"role": "restore", "db": "admin"},
                    {"role": "backup", "db": "admin"},
                    {"role": "clusterAdmin", "db": "admin"},
                    {"role": "readWriteAnyDatabase", "db": "admin"},
                    {"role": "dbAdminAnyDatabase", "db": "admin"},
                ],
                "param": {
                    "user": "mms-automation",
                    "db": "admin",
                    "mechanism": "SCRAM-SHA-1",
                },
                "result": 0,
            },
            "database": "database_name",
            "project": "project_name",
        }
    ]
    json_logs = atlas_api.convert_audit_logs_and_generate_id(
        [
            '{ "atype" : "authenticate", "ts" : { "$date" : "2020-01-30T16:02:59.770+0000" }, "local" : { "ip" : "127.0.0.1", "port" : 27017 }, "remote" : { "ip" : "127.0.0.1", "port" : 60406 }, "users" : [ { "user" : "mms-automation", "db" : "admin" } ], "roles" : [ { "role" : "userAdminAnyDatabase", "db" : "admin" }, { "role" : "restore", "db" : "admin" }, { "role" : "backup", "db" : "admin" }, { "role" : "clusterAdmin", "db" : "admin" }, { "role" : "readWriteAnyDatabase", "db" : "admin" }, { "role" : "dbAdminAnyDatabase", "db" : "admin" } ], "param" : { "user" : "mms-automation", "db" : "admin", "mechanism" : "SCRAM-SHA-1" }, "result" : 0 }'
        ],
        "shard_name",
        "database_name",
        "project_name",
    )
    assert json_logs == expected


def test_convert_access_logs_and_generate_id():
    expected = [
        {
            "id": "7b3a1f011d94dfc278e24c2835f0dc91703501e09ba546db709f06d8f22c34c0",
            "created": "2020-02-07T12:46:11.458+0000",
            "access_dump": {
                "authResult": "false",
                "authSource": "admin",
                "failureReason": "UserNotFound: Could not find user end-to-end@admin",
                "groupId": "5e16e8dbf2a30b1c7b43c5cf",
                "hostname": "izumi-test-shard-00-02-qibrg.mongodb.net",
                "ipAddress": "109.156.167.86",
                "logLine": "2020-02-07T12:46:11.458+0000 I ACCESS   [conn23129] SASL SCRAM-SHA-1 authentication failed for end-to-end on admin from client 109.156.167.86:52748 ; UserNotFound: Could not find user end-to-end@admin",
                "timestamp": "Fri Feb 07 12:46:11 GMT 2020",
                "username": "end-to-end",
            },
            "database": "clustername",
            "project": "project_name",
        }
    ]
    json_logs = atlas_api.convert_access_history_logs_and_generate_id(
        [
            {
                "authResult": "false",
                "authSource": "admin",
                "failureReason": "UserNotFound: Could not find user end-to-end@admin",
                "groupId": "5e16e8dbf2a30b1c7b43c5cf",
                "hostname": "izumi-test-shard-00-02-qibrg.mongodb.net",
                "ipAddress": "109.156.167.86",
                "logLine": "2020-02-07T12:46:11.458+0000 I ACCESS   [conn23129] SASL SCRAM-SHA-1 authentication failed for end-to-end on admin from client 109.156.167.86:52748 ; UserNotFound: Could not find user end-to-end@admin",
                "timestamp": "Fri Feb 07 12:46:11 GMT 2020",
                "username": "end-to-end",
            },
        ],
        "clustername",
        "project_name",
    )
    assert json_logs == expected


class TestGetLogFiles:
    def test_get_log_file(self, requests_mock, mock_config):
        expected = "2020-02-27T05:48:24.037+0000 I NETWORK  [conn373449] end connection 192.168.254.244:54430 (25 connections now open)\n"
        compressed_value = gzip.compress(bytes(expected, "utf-8"))
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/clusters/my_hostname/logs/mongodb.gz?startDate=1234&endDate=5678",
            content=compressed_value,
        )

        gen = atlas_api.get_log_file(
            "my_group",
            "my_hostname",
            "mongodb.gz",
            1234,
            5678,
            "database_name",
            "project_name",
        )
        assert list(gen)[0] == [
            {
                "component": "NETWORK",
                "hostname": "my_hostname",
                "context": "conn373449",
                "created": "2020-02-27T05:48:24.037+0000",
                "id": "e034e95e6b2ba237d0f972c803be63c246c49282f6dff49228422af4f8ba2681",
                "message": "end connection 192.168.254.244:54430 (25 connections now open)",
                "severity": "I",
                "database": "database_name",
                "project": "project_name",
            }
        ]

    @freeze_time(datetime.fromtimestamp(1234.56, timezone.utc))
    def test_get_log_file_none_start_date(
        self, requests_mock, mock_config_no_hwm_get_log_file
    ):
        expected = "2020-01-30T14:48:24.037+0000 I NETWORK  [conn373449] end connection 192.168.254.244:54430 (25 connections now open)\n"
        compressed_value = gzip.compress(bytes(expected, "utf-8"))
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/clusters/my_hostname/logs/mongodb.gz?startDate=234&endDate=1234",
            content=compressed_value,
        )
        gen = atlas_api.get_log_file(
            "my_group",
            "my_hostname",
            "mongodb.gz",
            None,
            None,
            "database_name",
            "project_name",
        )

        assert list(gen)[0] == [
            {
                "id": "c381467dfcd768ed19f0c30c178793be691321537a902019fe354b50c8160c05",
                "hostname": "my_hostname",
                "created": "2020-01-30T14:48:24.037+0000",
                "severity": "I",
                "component": "NETWORK",
                "context": "conn373449",
                "message": "end connection 192.168.254.244:54430 (25 connections now open)",
                "database": "database_name",
                "project": "project_name",
            }
        ]

    @freeze_time(datetime.fromtimestamp(1234.56, timezone.utc))
    def test_no_hwm_startdate(self, mock_config_no_hwm):
        assert atlas_api.no_hwm_startdate() == 234

    def test_invalid_log_name(self, requests_mock, mock_config):
        expected = "2020-01-30T14:48:24.037+0000 I NETWORK  [conn373449] end connection 192.168.254.244:54430 (25 connections now open)"
        compressed_value = gzip.compress(bytes(expected, "utf-8"))
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/clusters/my_hostname/logs/Not_a_defined_log?startDate=1580395704&endDate=1580482104",
            content=compressed_value,
        )
        with pytest.raises(AssertionError):
            atlas_api.get_log_file(
                "my_group",
                "my_hostname",
                "Not_a_defined_log",
                "2020-01-30T14:48:24.037+0000",
                "1",
                "database_name",
                "project_name",
            )


class TestGetOrgEvents:
    def test_success(self, requests_mock, mock_config):
        expected = json.dumps({"results": [{"id": "123"}]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/orgs/my_org/events?minDate=123&itemsPerPage=500&pageNum=1&maxDate=456",
            text=expected,
        )
        assert list(atlas_api.get_org_events("my_org", "123", "456"))[0] == [
            {"id": "123"}
        ]

    def test_success_empty_page_3(self, requests_mock, mock_config):
        expected = expected = json.dumps(
            {"results": [{"id": str(i)} for i in range(0, 500)]}
        )
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/orgs/my_org/events?minDate=123&itemsPerPage=500&pageNum=1&maxDate=456",
            text=expected,
        )
        expected2 = json.dumps({"results": [{"id": "456"}]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/orgs/my_org/events?minDate=123&itemsPerPage=500&pageNum=2&maxDate=456",
            text=expected2,
        )
        expected3 = json.dumps({"results": []})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/orgs/my_org/events?minDate=123&itemsPerPage=500&pageNum=3&maxDate=456",
            text=expected3,
        )
        gen = atlas_api.get_org_events("my_org", "123", "456")
        assert sum(len(x) for x in list(gen)) == 501

    def test_success_2_pages(self, requests_mock, mock_config):
        expected = expected = json.dumps(
            {"results": [{"id": str(i)} for i in range(0, 500)]}
        )
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/orgs/my_org/events?minDate=123&itemsPerPage=500&pageNum=1&maxDate=456",
            text=expected,
        )
        expected2 = json.dumps({"results": [{"id": "456"}]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/orgs/my_org/events?minDate=123&itemsPerPage=500&pageNum=2&maxDate=456",
            text=expected2,
        )
        gen = atlas_api.get_org_events("my_org", "123", "456")
        assert sum(len(x) for x in list(gen)) == 501

    def test_empty_response(self, requests_mock, mock_config):
        expected = json.dumps({"results": []})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/orgs/my_org/events?minDate=123&itemsPerPage=500&pageNum=1&maxDate=456",
            text=expected,
        )
        assert list(atlas_api.get_org_events("my_org", "123", "456"))[0] == []

    def test_none_min_date(self, requests_mock, mock_config):
        expected = json.dumps({"results": [{"id": "123"}]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/orgs/my_org/events?&itemsPerPage=500&pageNum=1",
            text=expected,
        )
        assert list(atlas_api.get_org_events("my_org", None, None))[0] == [
            {"id": "123"}
        ]

    def test_none_min_date_multi_page(self, requests_mock, mock_config):
        expected = json.dumps({"results": [{"id": str(i)} for i in range(0, 500)]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/orgs/my_org/events?&itemsPerPage=500&pageNum=1",
            text=expected,
        )
        expected2 = json.dumps({"results": [{"id": str(i)} for i in range(0, 500)]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/orgs/my_org/events?&itemsPerPage=500&pageNum=2",
            text=expected2,
        )
        expected3 = json.dumps({"results": [{"id": "123"}]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/orgs/my_org/events?&itemsPerPage=500&pageNum=3",
            text=expected3,
        )
        gen = atlas_api.get_org_events("my_org", None, None)
        assert sum(len(x) for x in list(gen)) == 1001


class TestGetGroupEvents:
    def test_success(self, requests_mock, mock_config):
        expected = json.dumps({"results": [{"id": "123"}]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?minDate=123&itemsPerPage=500&pageNum=1&maxDate=456",
            text=expected,
        )

        assert list(atlas_api.get_group_events("my_group", "123", "456"))[0] == [
            {"id": "123"}
        ]

    def test_success_empty_page_3(self, requests_mock, mock_config):
        expected = expected = json.dumps(
            {"results": [{"id": str(i)} for i in range(0, 500)]}
        )
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?minDate=123&itemsPerPage=500&pageNum=1&maxDate=456",
            text=expected,
        )
        expected2 = json.dumps({"results": [{"id": "456"}]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?minDate=123&itemsPerPage=500&pageNum=2&maxDate=456",
            text=expected2,
        )
        expected3 = json.dumps({"results": []})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?minDate=123&itemsPerPage=500&pageNum=3&maxDate=456",
            text=expected3,
        )
        gen = atlas_api.get_group_events("my_group", "123", "456")
        assert sum(len(x) for x in list(gen)) == 501

    def test_success_2_pages(self, requests_mock, mock_config):
        expected = expected = json.dumps(
            {"results": [{"id": str(i)} for i in range(0, 500)]}
        )
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?minDate=123&itemsPerPage=500&pageNum=1&maxDate=456",
            text=expected,
        )
        expected2 = json.dumps({"results": [{"id": "456"}]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?minDate=123&itemsPerPage=500&pageNum=2&maxDate=456",
            text=expected2,
        )
        gen = atlas_api.get_group_events("my_group", "123", "456")
        assert sum(len(x) for x in list(gen)) == 501

    def test_empty_response(self, requests_mock, mock_config):
        expected = json.dumps({"results": []})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?minDate=123&itemsPerPage=500&pageNum=1&maxDate=456",
            text=expected,
        )
        assert list(atlas_api.get_group_events("my_group", "123", "456"))[0] == []

    def test_none_min_date(self, requests_mock, mock_config):
        expected = json.dumps({"results": [{"id": "123"}]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?&itemsPerPage=500&pageNum=1",
            text=expected,
        )
        assert list(atlas_api.get_group_events("my_group", None, None))[0] == [
            {"id": "123"}
        ]

    def test_none_min_date_multi_page(self, requests_mock, mock_config):
        expected = json.dumps({"results": [{"id": str(i)} for i in range(0, 500)]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?&itemsPerPage=500&pageNum=1",
            text=expected,
        )
        expected2 = json.dumps({"results": [{"id": str(i)} for i in range(0, 500)]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?&itemsPerPage=500&pageNum=2",
            text=expected2,
        )
        expected3 = json.dumps({"results": [{"id": "123"}]})
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/events?&itemsPerPage=500&pageNum=3",
            text=expected3,
        )
        gen = atlas_api.get_group_events("my_group", None, None)
        assert sum(len(x) for x in list(gen)) == 1001


class TestGetAccessLogs:
    @freeze_time(datetime.fromtimestamp(1582886975.50, timezone.utc))
    def test_get_access_logs(self, requests_mock, mock_config):
        expected = json.dumps(
            {
                "accessLogs": [
                    {
                        "authResult": "false",
                        "authSource": "admin",
                        "failureReason": "UserNotFound: Could not find user end-to-end@admin",
                        "groupId": "5e16e8dbf2a30b1c7b43c5cf",
                        "hostname": "izumi-test-shard-00-02-qibrg.mongodb.net",
                        "ipAddress": "109.156.167.86",
                        "logLine": "2020-02-27T12:46:11.458+0000 I ACCESS   [conn23129] SASL SCRAM-SHA-1 authentication failed for end-to-end on admin from client 109.156.167.86:52748 ; UserNotFound: Could not find user end-to-end@admin",
                        "timestamp": "Fri Feb 27 12:46:11 GMT 2020",
                        "username": "end-to-end",
                    }
                ]
            }
        )
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/dbAccessHistory/clusters/my_clustername?start=1234000&end=5678000",
            text=expected,
        )
        assert atlas_api.get_access_logs(
            "my_group", "my_clustername", 1234000, 5678000, "project_name",
        ) == [
            {
                "id": "f696fc995d32f1c1c65c7cbe26111e7fa77ccc2c6a42afe7730e6c2949422109",
                "created": "2020-02-27T12:46:11.458+0000",
                "access_dump": {
                    "authResult": "false",
                    "authSource": "admin",
                    "failureReason": "UserNotFound: Could not find user end-to-end@admin",
                    "groupId": "5e16e8dbf2a30b1c7b43c5cf",
                    "hostname": "izumi-test-shard-00-02-qibrg.mongodb.net",
                    "ipAddress": "109.156.167.86",
                    "logLine": "2020-02-27T12:46:11.458+0000 I ACCESS   [conn23129] SASL SCRAM-SHA-1 authentication failed for end-to-end on admin from client 109.156.167.86:52748 ; UserNotFound: Could not find user end-to-end@admin",
                    "timestamp": "Fri Feb 27 12:46:11 GMT 2020",
                    "username": "end-to-end",
                },
                "database": "my_clustername",
                "project": "project_name",
            }
        ]

    def test_get_access_logs_multiple(self, requests_mock, mock_config):
        expected = json.dumps(
            {
                "accessLogs": [
                    {
                        "authResult": "false",
                        "authSource": "admin",
                        "failureReason": "UserNotFound: Could not find user end-to-end@admin",
                        "groupId": "5e16e8dbf2a30b1c7b43c5cf",
                        "hostname": "izumi-test-shard-00-02-qibrg.mongodb.net",
                        "ipAddress": "109.156.167.86",
                        "logLine": "2020-01-27T12:46:11.458+0000 I ACCESS   [conn23129] SASL SCRAM-SHA-1 authentication failed for end-to-end on admin from client 109.156.167.86:52748 ; UserNotFound: Could not find user end-to-end@admin",
                        "timestamp": "Fri Jan 27 12:46:11 GMT 2020",
                        "username": "end-to-end",
                    },
                    {
                        "authResult": "false",
                        "authSource": "admin",
                        "failureReason": "UserNotFound: Could not find user end-to-end@admin",
                        "groupId": "5e16e8dbf2a30b1c7b43c5cf",
                        "hostname": "izumi-test-shard-00-02-qibrg.mongodb.net",
                        "ipAddress": "109.156.167.86",
                        "logLine": "2020-02-27T12:46:11.458+0000 I ACCESS   [conn23129] SASL SCRAM-SHA-1 authentication failed for end-to-end on admin from client 109.156.167.86:52748 ; UserNotFound: Could not find user end-to-end@admin",
                        "timestamp": "Fri Feb 27 12:46:11 GMT 2020",
                        "username": "end-to-end",
                    },
                ]
            }
        )
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/dbAccessHistory/clusters/my_clustername?start=1234000&end=5678000",
            text=expected,
        )
        assert atlas_api.get_access_logs(
            "my_group", "my_clustername", 1234000, 5678000, "project_name",
        ) == [
            {
                "id": "c44bc6e0707ce5b14b123a0b3e78cd98dc0eb53fed37aabf52b3c2262783c945",
                "created": "2020-01-27T12:46:11.458+0000",
                "access_dump": {
                    "authResult": "false",
                    "authSource": "admin",
                    "failureReason": "UserNotFound: Could not find user end-to-end@admin",
                    "groupId": "5e16e8dbf2a30b1c7b43c5cf",
                    "hostname": "izumi-test-shard-00-02-qibrg.mongodb.net",
                    "ipAddress": "109.156.167.86",
                    "logLine": "2020-01-27T12:46:11.458+0000 I ACCESS   [conn23129] SASL SCRAM-SHA-1 authentication failed for end-to-end on admin from client 109.156.167.86:52748 ; UserNotFound: Could not find user end-to-end@admin",
                    "timestamp": "Fri Jan 27 12:46:11 GMT 2020",
                    "username": "end-to-end",
                },
                "database": "my_clustername",
                "project": "project_name",
            },
            {
                "id": "f696fc995d32f1c1c65c7cbe26111e7fa77ccc2c6a42afe7730e6c2949422109",
                "created": "2020-02-27T12:46:11.458+0000",
                "access_dump": {
                    "authResult": "false",
                    "authSource": "admin",
                    "failureReason": "UserNotFound: Could not find user end-to-end@admin",
                    "groupId": "5e16e8dbf2a30b1c7b43c5cf",
                    "hostname": "izumi-test-shard-00-02-qibrg.mongodb.net",
                    "ipAddress": "109.156.167.86",
                    "logLine": "2020-02-27T12:46:11.458+0000 I ACCESS   [conn23129] SASL SCRAM-SHA-1 authentication failed for end-to-end on admin from client 109.156.167.86:52748 ; UserNotFound: Could not find user end-to-end@admin",
                    "timestamp": "Fri Feb 27 12:46:11 GMT 2020",
                    "username": "end-to-end",
                },
                "database": "my_clustername",
                "project": "project_name",
            },
        ]

    def test_get_access_logs_none(self, requests_mock, mock_config):
        expected = json.dumps(
            {
                "accessLogs": [
                    {
                        "authResult": "false",
                        "authSource": "admin",
                        "failureReason": "UserNotFound: Could not find user end-to-end@admin",
                        "groupId": "5e16e8dbf2a30b1c7b43c5cf",
                        "hostname": "izumi-test-shard-00-02-qibrg.mongodb.net",
                        "ipAddress": "109.156.167.86",
                        "logLine": "2020-02-27T12:46:11.458+0000 I ACCESS   [conn23129] SASL SCRAM-SHA-1 authentication failed for end-to-end on admin from client 109.156.167.86:52748 ; UserNotFound: Could not find user end-to-end@admin",
                        "timestamp": "Fri Feb 27 12:46:11 GMT 2020",
                        "username": "end-to-end",
                    }
                ]
            }
        )
        requests_mock.register_uri(
            "GET",
            "https://cloud.mongodb.com/api/atlas/v1.0/groups/my_group/dbAccessHistory/clusters/my_clustername",
            text=expected,
        )
        assert atlas_api.get_access_logs(
            "my_group", "my_clustername", None, None, "project_name",
        ) == [
            {
                "id": "f696fc995d32f1c1c65c7cbe26111e7fa77ccc2c6a42afe7730e6c2949422109",
                "created": "2020-02-27T12:46:11.458+0000",
                "access_dump": {
                    "authResult": "false",
                    "authSource": "admin",
                    "failureReason": "UserNotFound: Could not find user end-to-end@admin",
                    "groupId": "5e16e8dbf2a30b1c7b43c5cf",
                    "hostname": "izumi-test-shard-00-02-qibrg.mongodb.net",
                    "ipAddress": "109.156.167.86",
                    "logLine": "2020-02-27T12:46:11.458+0000 I ACCESS   [conn23129] SASL SCRAM-SHA-1 authentication failed for end-to-end on admin from client 109.156.167.86:52748 ; UserNotFound: Could not find user end-to-end@admin",
                    "timestamp": "Fri Feb 27 12:46:11 GMT 2020",
                    "username": "end-to-end",
                },
                "database": "my_clustername",
                "project": "project_name",
            }
        ]
