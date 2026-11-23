import json
from pathlib import Path

import jsonschema
import pytest

from wgoctopus_orch.awgparams import generate_obfuscation, validate_obfuscation
from wgoctopus_orch.renderer import render_node_state
from wgoctopus_orch.service import create_instance, create_node, place


@pytest.mark.parametrize("version", ["2.0", "3.0", "3.1"])
@pytest.mark.parametrize("intensity", ["low", "medium", "high"])
@pytest.mark.parametrize("mtu", [1280, 1500])
def test_generated_values(version, intensity, mtu):
    for _ in range(500):
        value = generate_obfuscation(version, mtu, intensity)
        assert validate_obfuscation(value, mtu=mtu, version=version) == []
        assert value["jmin"] < value["jmax"] <= mtu - 28
        padded = [value["s1"] + 148, value["s2"] + 92, value["s3"] + 64, value["s4"] + 32]
        assert len(set(padded)) == 4
        assert version == "2.0" or all(value[f"s{i}"] >= 12 for i in range(1, 5))
        ranges = [tuple(map(int, value[f"h{i}"].split("-"))) for i in range(1, 5)]
        assert all(1000 <= hi - lo <= 50000 and hi <= 0xFFFFFFFF for lo, hi in ranges)
        assert all(max(a, c) > min(b, d) for i, (a, b) in enumerate(ranges) for c, d in ranges[i + 1:])


def test_different_draws_and_unsupported_version():
    assert len({generate_obfuscation()["h1"] for _ in range(50)}) > 40
    with pytest.raises(ValueError):
        generate_obfuscation("1.5")
    with pytest.raises(ValueError):
        generate_obfuscation(intensity="extreme")


def test_validation_missing_and_unparseable_fields():
    assert any("missing key" in e for e in validate_obfuscation({}))
    value = generate_obfuscation()
    value["h1"] = "not-a-range"
    assert any("invalid h1" in e for e in validate_obfuscation(value))


def test_small_mtu_repairs_and_header_slide():
    # Fixed values force the small-MTU repair and end-of-client H window slide.
    class Draw:
        def __call__(self, lo, hi):
            if (lo, hi) == (-1, 1): return 0
            if (lo, hi) == (128, 512): return 500
            if (lo, hi) == (512, 1024): return 512
            if (lo, hi) == (0, 64): return 0
            if (lo, hi) == (1000, 50000): return 1000
            if lo > 1_000_000: return hi
            return lo
    value = generate_obfuscation(mtu=200, rnd=Draw(), client_max_h=3_600_001_000)
    assert value["jmax"] <= 172 and value["jmin"] < value["jmax"]
    assert int(value["h4"].split("-")[1]) <= 3_600_001_000


def test_validation_rejects_bad_ranges_and_values():
    value = generate_obfuscation()
    value.update(jmin=500, jmax=200, s1=1, s2=57, h1="1-4", h2="2-8")
    errors = validate_obfuscation(value)
    assert any("Jmin" in e for e in errors)
    assert any("S collision" in e for e in errors)
    assert any("H ranges overlap" in e for e in errors)
    assert any("disabled" in e for e in errors)


def test_instance_default_renders_schema_valid_state(session, crypto):
    instance = create_instance(session, "awg0", 51820, "10.22.0.1/29", crypto=crypto, mtu=1400)
    assert validate_obfuscation(instance.obfuscation, mtu=1400) == []
    node = create_node(session, "node-a", "203.0.113.10", "operator", agent_token="fake", crypto=crypto)
    place(session, instance.id, node.id, crypto=crypto)
    state = render_node_state(session, node.id, crypto)
    with Path("../schema/state.schema.json").open(encoding="utf-8") as f:
        jsonschema.validate(state, json.load(f))
