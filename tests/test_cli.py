from __future__ import annotations

import json
from pathlib import Path

import pytest

from scan2pddl_alfa.cli import build_pddl_problem


def test_nmap_xml_with_overlay_renders_alfa_style_problem() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    xml_path = repo_root / "examples" / "alfa_motivating_scan.xml"
    overlay_path = repo_root / "examples" / "alfa_motivating_overlay.json"

    problem = build_pddl_problem(xml_path, overlay_path=overlay_path)

    assert "(connected_to_network attacker_host dmz)" in problem
    assert "(connected_to_network web_server dmz)" in problem
    assert "(connected_to_network web_server lan)" in problem
    assert "(connected_to_network db_server lan)" in problem
    assert "(has_product web_server a--drupal--drupal)" in problem
    assert "(has_version web_server a--drupal--drupal ma8 mi6 pa9)" in problem
    assert "(TCP_listen db_server a--apache--couchdb)" in problem
    assert "(is_compromised db_server agent ROOT_PRIVILEGES)" in problem


def test_json_inventory_can_drive_problem_generation(tmp_path: Path) -> None:
    payload = {
        "goal_host": "app_server",
        "attacker_networks": ["edge"],
        "hosts": [
            {
                "name": "app-server",
                "ip": "10.0.0.7",
                "networks": ["edge"],
                "products": [
                    {
                        "cpe": "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
                    }
                ],
                "services": [
                    {
                        "protocol": "tcp",
                        "cpe": "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*",
                    }
                ],
            }
        ],
    }
    input_path = tmp_path / "inventory.json"
    input_path.write_text(json.dumps(payload), encoding="utf-8")

    problem = build_pddl_problem(input_path)

    assert "(connected_to_network attacker_host edge)" in problem
    assert "(has_product app_server a--apache--http_server)" in problem
    assert "(has_version app_server a--apache--http_server ma2 mi4 pa58)" in problem
    assert "(TCP_listen app_server a--apache--http_server)" in problem


def test_missing_goal_host_is_rejected(tmp_path: Path) -> None:
    payload = {
        "attacker_networks": ["edge"],
        "hosts": [
            {
                "name": "app-server",
                "ip": "10.0.0.7",
                "networks": ["edge"],
            }
        ],
    }
    input_path = tmp_path / "inventory.json"
    input_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="goal_host"):
        build_pddl_problem(input_path)
