from wgoctopus_orch.agent_metrics import extract_peer_stats, parse_agent_metrics


def test_empty_or_invalid_metrics_have_no_samples():
    assert parse_agent_metrics("") == []
    assert parse_agent_metrics("  \n garbage\nnot a metric") == []


def test_parser_comments_escapes_nonfinite_and_garbage():
    metrics = parse_agent_metrics(r'''# HELP demo

wg_interface_up{interface="wg0",note="a\\b\"c\nline"} 1
wg_peer_last_handshake_timestamp_seconds{interface="wg0",public_key="secret"} +Inf
drop NaN
broken{label=x} 3
''')
    assert len(metrics) == 2
    assert metrics[0].labels["note"] == 'a\\b"c\nline'
    assert metrics[1].value == float("inf")


def test_extracts_interfaces_and_peers():
    samples = parse_agent_metrics('''
wg_interface_up{interface="wg0"} 1
wg_peer_last_handshake_timestamp_seconds{interface="wg0",public_key="k"} 0
wg_peer_rx_bytes_total{interface="wg0",public_key="k"} 8
wg_peer_tx_bytes_total{interface="wg0",public_key="k"} 9
wg_interface_up{interface="wg1"} 0
''')
    interfaces, peers = extract_peer_stats(samples)
    assert interfaces == {"wg0": {"up": True}, "wg1": {"up": False}}
    assert peers[("wg0", "k")].rx == 8
    assert peers[("wg0", "k")].tx == 9
    assert peers[("wg0", "k")].handshake_ts == 0
