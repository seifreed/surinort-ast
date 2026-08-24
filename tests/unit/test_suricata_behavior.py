import json

from tools.suricata_behavior import alert_projection


def test_alert_projection_ignores_runtime_fields_and_non_alert_events(tmp_path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text(
        "\n".join(
            [
                json.dumps({"event_type": "flow", "flow_id": 1}),
                json.dumps(
                    {
                        "event_type": "alert",
                        "timestamp": "different-on-every-run",
                        "alert": {
                            "signature_id": 1001,
                            "signature": "HTTP request",
                            "gid": 1,
                            "rev": 1,
                            "action": "allowed",
                            "category": "",
                            "severity": 3,
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    assert alert_projection(eve) == (
        {
            "action": "allowed",
            "category": "",
            "gid": 1,
            "rev": 1,
            "severity": 3,
            "signature": "HTTP request",
            "signature_id": 1001,
        },
    )
