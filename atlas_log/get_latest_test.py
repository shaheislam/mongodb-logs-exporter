# from atlas_log import get_latest


# def test_get_latest_group_events(monkeypatch):
#     def mock_get_alerts(group_id, min_date):
#         assert group_id == "my-group"
#         assert min_date == "123"
#         return [
#             {"id": "id_2", "created": "456"},
#         ]

#     def mock_create_iterator(fn, watermark_id):
#         assert watermark_id == "NdapAtlasLogs/cursors/groups/my-group.json"
#         return get_latest.high_watermark.HighWatermarkCursor(
#             fn({"id": "id_1", "min_date": "123"}), "my-iterator", None
#         )

#     monkeypatch.setattr(get_latest.atlas_api, "get_group_events", mock_get_alerts)
#     monkeypatch.setattr(
#         get_latest.high_watermark.HighWatermarkCursor, "create", mock_create_iterator
#     )
#     assert get_latest.get_latest_group_events("my-group").events == [
#         {"id": "id_2", "created": "456"}
#     ]


# def test_get_latest_org_events(monkeypatch):
#     def mock_get_alerts(org_id, min_date):
#         assert org_id == "my-org"
#         assert min_date == "123"
#         return [
#             {"id": "id_2", "created": "456"},
#         ]

#     def mock_create_iterator(fn, watermark_id):
#         assert watermark_id == "NdapAtlasLogs/cursors/orgs/my-org.json"
#         return get_latest.high_watermark.HighWatermarkCursor(
#             fn({"id": "id_1", "min_date": "123"}), "my-iterator", None
#         )

#     monkeypatch.setattr(get_latest.atlas_api, "get_org_events", mock_get_alerts)
#     monkeypatch.setattr(
#         get_latest.high_watermark.HighWatermarkCursor, "create", mock_create_iterator
#     )
#     assert get_latest.get_latest_org_events("my-org").events == [
#         {"id": "id_2", "created": "456"}
#     ]
