"""Pure parsers and validators for offline WireGuard instance imports."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from sqlalchemy import delete, select

from . import service
from .awgcps import validate_cps_chain
from .awgparams import validate_3x_fields
from .config import database_url
from .crypto import Crypto
from .db import make_engine, make_session_factory, upgrade_to_head
from .keys import derive_public
from .models import Event, Instance, Node, Peer, Placement
from .renderer import render_node_state


@dataclass(frozen=True)
class Warning:
    code: str
    count: int


@dataclass(frozen=True)
class Problem:
    code: str
    field: str


@dataclass
class ParsedPeer:
    name: str
    public_key: str
    private_key: str | None
    preshared_key: str | None
    allowed_ip: str
    enabled: bool
    owner: str | None


@dataclass
class ParsedInstance:
    kind: str
    listen_port: int
    address: str
    private_key: str
    public_key: str
    obfuscation: dict[str, Any]
    mtu: int | None = None
    endpoint_host: str | None = None
    client_dns: list[str] | None = None
    client_keepalive: int | None = None
    client_allowed_ips: list[str] | None = None
    peers: list[ParsedPeer] = field(default_factory=list)
    warnings: list[Warning] = field(default_factory=list)


class ImportFailure(ValueError):
    """Structural import error represented by a stable, value-free code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _failure(code: str) -> ImportFailure:
    return ImportFailure(code)


def _verified_private(private: str, public: str) -> None:
    try:
        matches = derive_public(private) == public
    except (ValueError, TypeError):
        matches = False
    if not matches:
        raise _failure("KEY_MISMATCH")


def _unique_peers(peers: list[ParsedPeer]) -> None:
    ips: set[str] = set()
    keys: set[str] = set()
    for peer in peers:
        if peer.allowed_ip in ips:
            raise _failure("DUPLICATE_PEER_IP")
        if peer.public_key in keys:
            raise _failure("DUPLICATE_PEER_KEY")
        ips.add(peer.allowed_ip)
        keys.add(peer.public_key)


def _wg_conf(directory: Path) -> dict[str, str]:
    for path in sorted((directory / "server_peers").glob("peer*.conf")):
        values: dict[str, str] = {}
        for line in path.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep:
                values[key.strip()] = value.strip()
        if values:
            return values
    return {}


def _split_list(value: Any) -> list[str] | None:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            decoded = value
        if isinstance(decoded, list):
            return [str(item).strip() for item in decoded if str(item).strip()]
        value = decoded
    if isinstance(value, list):
        result = [str(item).strip() for item in value if str(item).strip()]
    else:
        result = [item.strip() for item in str(value).split(",") if item.strip()]
    return result or None


def parse_amnezia(source_dir: str | Path) -> ParsedInstance:
    """Parse an Amnezia config directory without modifying it."""
    root = Path(source_dir)
    path = root / "config" / "config.json"
    if not path.is_file():
        raise _failure("MISSING_FILE")
    try:
        data = json.loads(path.read_text())
        if "server" not in data and len(data) == 1:
            data = next(iter(data.values()))
        server, raw_peers = data["server"], data["peers"]
        keys = server["keys"]
        private, public = keys["private_key"], keys["public_key"]
        address = server["address"]
        port = int(server.get("port", server.get("listen_port")))
    except (OSError, ValueError, TypeError, KeyError, StopIteration):
        raise _failure("BAD_STRUCTURE") from None
    _verified_private(private, public)
    obfuscation = {key: server.get("junk", {}).get(key) for key in (
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4"
    ) if server.get("junk", {}).get(key) is not None}
    obfuscation.update({key: str(server.get("junk", {}).get(key)) for key in (
        "h1", "h2", "h3", "h4"
    ) if server.get("junk", {}).get(key) is not None})
    peers = []
    try:
        for key, peer in raw_peers.items():
            ip = str(peer["ip"]).split("/", 1)[0]
            peers.append(ParsedPeer(str(peer.get("name", key)), peer["public_key"],
                                    peer.get("private_key"), peer.get("preshared_key"),
                                    ip, True, None))
    except (AttributeError, KeyError, TypeError):
        raise _failure("BAD_STRUCTURE") from None
    _unique_peers(peers)
    conf = _wg_conf(root)
    return ParsedInstance("amnezia", port, address, private, public, obfuscation,
                          endpoint_host=server.get("endpoint"),
                          client_dns=_split_list(conf.get("DNS")),
                          client_keepalive=_int_or_none(conf.get("PersistentKeepalive")),
                          client_allowed_ips=_split_list(conf.get("AllowedIPs")),
                          peers=peers)


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None and str(value).strip() else None
    except (TypeError, ValueError):
        return None


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')}


def _first(conn: sqlite3.Connection, table: str) -> dict[str, Any]:
    if not _columns(conn, table):
        raise _failure("BAD_STRUCTURE")
    conn.row_factory = sqlite3.Row
    row = conn.execute(f'SELECT * FROM "{table}" LIMIT 1').fetchone()
    if row is None:
        raise _failure("BAD_STRUCTURE")
    return dict(row)


def _bool(value: Any) -> bool:
    return value is True or str(value).strip().lower() in ("1", "on", "true")


def _count_warnings(warnings: list[Warning]) -> list[Warning]:
    counts: dict[str, int] = {}
    for warning in warnings:
        counts[warning.code] = counts.get(warning.code, 0) + warning.count
    return [Warning(code, count) for code, count in sorted(counts.items())]


def parse_wgeasy(source_dir: str | Path, bot_db: str | Path | None = None) -> ParsedInstance:
    """Parse a wg-easy SQLite backup opened strictly read-only."""
    path = Path(source_dir) / "wg-easy.db"
    if not path.is_file():
        raise _failure("MISSING_FILE")
    warnings: list[Warning] = []
    try:
        conn = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
        interface = _first(conn, "interfaces_table")
        if not {"name", "port", "private_key", "public_key", "ipv4_cidr"} <= interface.keys():
            raise _failure("BAD_STRUCTURE")
        _verified_private(interface["private_key"], interface["public_key"])
        network = ipaddress.ip_interface(interface["ipv4_cidr"])
        address = f"{next(network.network.hosts())}/{network.network.prefixlen}"
        obf: dict[str, Any] = {}
        for key in ("j_c", "j_min", "j_max", "s1", "s2", "s3", "s4"):
            if interface.get(key) is not None:
                obf["jc" if key == "j_c" else "jmin" if key == "j_min" else
                    "jmax" if key == "j_max" else key] = int(interface[key])
        for key in ("h1", "h2", "h3", "h4"):
            if interface.get(key) is not None:
                obf[key] = str(interface[key])
        extras = ("header_protection_key", "content_padding_addition", "rekey_after_time",
                  "rekey_timeout", "reject_after_time", "keepalive_timeout",
                  "max_handshake_attempts", "random_trailers")
        for key in extras:
            value = interface.get(key)
            if value is not None:
                obf[key] = str(value) if key != "random_trailers" else _bool(value)
        if interface.get("disable_cookies") is not None and _bool(interface["disable_cookies"]):
            obf["disable_cookies"] = True
        for index in range(1, 6):
            value = interface.get(f"i{index}")
            if value:
                obf[f"i{index}"] = value
        user = _first(conn, "user_configs_table")
        for index in range(1, 6):
            key = f"i{index}"
            if not obf.get(key) and user.get(f"default_{key}"):
                obf[key] = user[f"default_{key}"]
        ipv6 = interface.get("ipv6_cidr")
        if ipv6:
            warnings.append(Warning("IPV6_IGNORED", 1))
        peers = []
        client_columns = _columns(conn, "clients_table")
        if not client_columns:
            raise _failure("BAD_STRUCTURE")
        conn.row_factory = sqlite3.Row
        client_rows = [dict(row) for row in conn.execute('SELECT * FROM "clients_table"')]
        for client in client_rows:
            if any(client.get(key) is not None for key in ("persistent_keepalive", "dns", "allowed_ips")):
                warnings.append(Warning("CLIENT_OVERRIDES_IGNORED", 1))
            if any(client.get(f"i{i}") for i in range(1, 6)) or any(
                client.get(key) is not None for key in ("j_c", "j_min", "j_max")
            ):
                warnings.append(Warning("CLIENT_CPS_IGNORED", 1))
            peers.append(ParsedPeer(str(client.get("name", "")), client["public_key"],
                                    client.get("private_key"), client.get("pre_shared_key"),
                                    str(client.get("ipv4_address", "")).split("/", 1)[0],
                                    _bool(client.get("enabled")), None))
        if bot_db is not None:
            owners: dict[str, str] = {}
            with sqlite3.connect(f"file:{Path(bot_db).resolve()}?mode=ro", uri=True) as bot:
                bot.row_factory = sqlite3.Row
                rows = [dict(row) for row in bot.execute('SELECT * FROM "peers"')]
            ids = {str(c.get("id")) for c in client_rows}
            owners = {str(row["client_id"]): str(row["owner"]) for row in rows
                      if row.get("client_id") is not None and row.get("owner") is not None}
            linked: set[str] = set()
            for client, peer in zip(client_rows, peers):
                ident = str(client.get("id"))
                if ident in owners:
                    peer.owner = owners[ident]
                    linked.add(ident)
            warnings.extend((Warning("BOT_ORPHANS", sum(str(row.get("client_id")) not in ids for row in rows)),
                             Warning("BOT_UNMAPPED", len(set(owners) & ids - linked))))
        _unique_peers(peers)
        return ParsedInstance("wgeasy", int(interface["port"]), address,
                              interface["private_key"], interface["public_key"], obf,
                              mtu=_int_or_none(interface.get("mtu")),
                              endpoint_host=user.get("host"), client_dns=_split_list(user.get("default_dns")),
                              client_keepalive=_int_or_none(user.get("default_persistent_keepalive")),
                              client_allowed_ips=_split_list(user.get("default_allowed_ips")),
                              peers=peers, warnings=_count_warnings(warnings))
    except ImportFailure:
        raise
    except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, StopIteration):
        raise _failure("BAD_STRUCTURE") from None
    finally:
        if "conn" in locals():
            conn.close()


def validate_parsed(parsed: ParsedInstance) -> list[Problem]:
    """Return all validation findings without including imported values."""
    result: list[Problem] = []
    obf = parsed.obfuscation
    for key, value in obf.items():
        if isinstance(value, str) and "<c>" in value:
            result.append(Problem("CPS_UNSUPPORTED_TAG", key))
    for error in validate_cps_chain({f"i{i}": str(obf.get(f"i{i}", "")) for i in range(1, 6)}):
        field_name = error.split(":", 1)[0] if ":" in error else "i1..i5"
        result.append(Problem("INVALID_CPS", field_name))
    try:
        result.extend(Problem("INVALID_3X_FIELD", e.split(":", 1)[0].replace("invalid ", ""))
                      for e in validate_3x_fields(obf))
    except (TypeError, ValueError):
        result.append(Problem("INVALID_3X_FIELD", "obfuscation"))
    if obf.get("header_protection_key") and any(_int_or_none(obf.get(f"s{i}")) is None or
                                                  _int_or_none(obf.get(f"s{i}")) < 12
                                                  for i in range(1, 5)):
        result.append(Problem("S_HEADER_MINIMUM", "s1..s4"))
    ranges: list[tuple[int, int]] = []
    for i in range(1, 5):
        key, value = f"h{i}", obf.get(f"h{i}")
        if value is None or value == "":
            continue
        match = re.fullmatch(r"\s*(\d+)\s*(?:-\s*(\d+)\s*)?", str(value))
        if not match:
            result.append(Problem("H_RANGE", key))
            continue
        low, high = int(match[1]), int(match[2] or match[1])
        if high < low or high > 0xFFFFFFFF:
            result.append(Problem("H_RANGE", key))
            continue
        if any(low <= old_high and old_low <= high for old_low, old_high in ranges):
            result.append(Problem("H_OVERLAP", key))
        ranges.append((low, high))
    if _int_or_none(obf.get("jmin")) is not None and _int_or_none(obf.get("jmax")) is not None and int(obf["jmin"]) > int(obf["jmax"]):
        result.append(Problem("J_RANGE", "jmin"))
    try:
        interface = ipaddress.ip_interface(parsed.address)
        server_ip = interface.ip
    except ValueError:
        result.append(Problem("ADDRESS_INVALID", "address"))
        return result
    seen_ips: set[str] = set()
    seen_keys: set[str] = set()
    for index, peer in enumerate(parsed.peers):
        field_name = f"peers[{index}]"
        try:
            ip = ipaddress.ip_address(peer.allowed_ip)
            if (ip not in interface.network or ip == server_ip or ip == interface.network.network_address or
                    (isinstance(interface.network, ipaddress.IPv4Network) and ip == interface.network.broadcast_address)):
                result.append(Problem("PEER_IP_OUT_OF_SUBNET", f"{field_name}.allowed_ip"))
        except ValueError:
            result.append(Problem("PEER_IP_OUT_OF_SUBNET", f"{field_name}.allowed_ip"))
        if peer.allowed_ip in seen_ips:
            result.append(Problem("DUPLICATE_PEER_IP", f"{field_name}.allowed_ip"))
        if peer.public_key in seen_keys:
            result.append(Problem("DUPLICATE_PEER_KEY", f"{field_name}.public_key"))
        seen_ips.add(peer.allowed_ip)
        seen_keys.add(peer.public_key)
        if not peer.private_key:
            parsed.warnings.append(Warning("PEER_NO_PRIVATE_KEY", 1))
        else:
            try:
                mismatch = derive_public(peer.private_key) != peer.public_key
            except (ValueError, TypeError):
                mismatch = True
            if mismatch:
                result.append(Problem("PEER_KEY_MISMATCH", f"{field_name}.private_key"))
    return result


def awg_features(parsed: ParsedInstance) -> dict[str, Any]:
    """Summarize configured 3.x features and non-empty CPS packet count."""
    names = {"header_protection_key", "content_padding_addition", "rekey_after_time",
             "rekey_timeout", "reject_after_time", "keepalive_timeout",
             "max_handshake_attempts", "random_trailers", "disable_cookies"}
    return {"fields": sorted(names & parsed.obfuscation.keys()),
            "cps_count": sum(bool(parsed.obfuscation.get(f"i{i}")) for i in range(1, 6))}


def _validate(obfuscation: dict[str, Any]) -> list[tuple[str, str]]:
    """Compatibility wrapper for the former obfuscation-only validator."""
    parsed = ParsedInstance("", 0, "0.0.0.0/0", "", "", obfuscation)
    return [(problem.code, problem.field) for problem in validate_parsed(parsed)
            if problem.code not in ("ADDRESS_INVALID", "PEER_NO_PRIVATE_KEY")]


def _parse(kind: str, source: str | Path) -> ParsedInstance:
    """Compatibility wrapper for old internal parser callers."""
    if kind == "amnezia":
        return parse_amnezia(source)
    if kind == "wgeasy":
        return parse_wgeasy(source)
    raise _failure("BAD_STRUCTURE")


def _wg0_peers(path: str | Path) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    public = None
    for line in Path(path).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("["):
            public = None
        elif "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            if key.lower() == "publickey":
                public = value
            elif key.lower() == "allowedips" and public:
                for item in value.split(","):
                    try:
                        address = ipaddress.ip_interface(item.strip())
                    except ValueError:
                        continue
                    if address.version == 4:
                        result.add((public, str(address.ip)))
    return result


def _apply(session, parsed: ParsedInstance, name: str, crypto: Crypto) -> Instance:
    instance = service.create_instance(
        session, name, parsed.listen_port, parsed.address, private_key=parsed.private_key,
        obfuscation=parsed.obfuscation or None, mtu=parsed.mtu, endpoint_host=parsed.endpoint_host,
        client_dns=", ".join(parsed.client_dns) if parsed.client_dns else None,
        client_keepalive=parsed.client_keepalive,
        client_allowed_ips=", ".join(parsed.client_allowed_ips) if parsed.client_allowed_ips else None,
        crypto=crypto,
    )
    for peer in parsed.peers:
        service.import_peer(session, instance.id, peer.name, public_key=peer.public_key,
                            private_key=peer.private_key, preshared_key=peer.preshared_key,
                            allowed_ip=peer.allowed_ip, enabled=peer.enabled,
                            owner=peer.owner, crypto=crypto)
    return instance


def _database_url(value: str | None) -> str:
    url = value or database_url()
    return url if "://" in url else f"sqlite:///{Path(url).resolve()}"


def run_import(kind: str, source: str | Path, name: str, *, dry_run: bool = False,
               verify_wg0: str | Path | None = None, bot_db: str | Path | None = None,
               db_url: str | None = None, crypto: Crypto | None = None,
               out=sys.stdout) -> int:
    """Validate, stage, render, and optionally commit an offline import."""
    parsed = None
    problems: list[Problem] = []
    verify = "skipped"
    checksum = "-"
    rendered_peers = 0
    status, result = "DRY-RUN" if dry_run else "COMMITTED", "OK"
    failure = None
    try:
        parsed = parse_amnezia(source) if kind == "amnezia" else parse_wgeasy(source, bot_db)
        problems = validate_parsed(parsed)
        if problems:
            failure, result = "VALIDATION_FAILED", "FAILED"
        if verify_wg0 and not failure:
            source_peers = {(peer.public_key, peer.allowed_ip) for peer in parsed.peers if peer.enabled}
            wg_peers = _wg0_peers(verify_wg0)
            matched = len(source_peers & wg_peers)
            verify = f"matched={matched} only_source={len(source_peers - wg_peers)} only_wg0={len(wg_peers - source_peers)}"
            if source_peers != wg_peers:
                failure, result = "WG0_MISMATCH", "FAILED"
        if not failure:
            with tempfile.TemporaryDirectory() as temporary:
                staging_url = f"sqlite:///{Path(temporary) / 'staging.db'}"
                upgrade_to_head(staging_url)
                engine = make_engine(staging_url)
                factory = make_session_factory(engine)
                stage_crypto = Crypto(Fernet.generate_key())
                with factory() as session:
                    instance = _apply(session, parsed, name, stage_crypto)
                    node = Node(name="staging", ssh_host="192.0.2.1", ssh_user="staging",
                                mgmt_mode="push", agent_token_enc=stage_crypto.encrypt("staging"))
                    session.add(node)
                    session.flush()
                    session.add(Placement(instance_id=instance.id, node_id=node.id, role="active", weight=1))
                    session.commit()
                    state = render_node_state(session, node.id, stage_crypto)
                    canonical = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
                    checksum = hashlib.sha256(canonical).hexdigest()
                    rendered_peers = sum(len(interface.get("peers", [])) for interface in state["interfaces"])
                engine.dispose()
            if not dry_run:
                url = _database_url(db_url)
                if os.getenv("WGOCTOPUS_AUTO_MIGRATE", "true").lower() == "true":
                    upgrade_to_head(url)
                engine = make_engine(url)
                factory = make_session_factory(engine)
                try:
                    with factory() as session:
                        if session.scalar(select(Instance.id).where(
                                (Instance.name == name) | (Instance.listen_port == parsed.listen_port))):
                            failure, result = "DUPLICATE_INSTANCE", "FAILED"
                        else:
                            try:
                                real_crypto = crypto or Crypto()
                            except RuntimeError:
                                failure, result = "MASTER_KEY_MISSING", "FAILED"
                            if not failure:
                                try:
                                    instance = _apply(session, parsed, name, real_crypto)
                                except Exception as exc:  # noqa: BLE001 - every apply failure needs cleanup
                                    session.rollback()
                                    failure, result = f"APPLY_FAILED:{type(exc).__name__}", "FAILED"
                                    created = session.scalar(select(Instance).where(Instance.name == name))
                                    if created:
                                        peer_ids = session.scalars(select(Peer.id).where(
                                            Peer.instance_id == created.id)).all()
                                        subjects = [str(created.id), *(str(peer_id) for peer_id in peer_ids)]
                                        session.execute(delete(Peer).where(Peer.instance_id == created.id))
                                        session.delete(created)
                                        session.execute(delete(Event).where(Event.subject.in_(subjects)))
                                        session.commit()
                finally:
                    engine.dispose()
    except ImportFailure as exc:
        failure, result = exc.code, "FAILED"
    except Exception as exc:  # noqa: BLE001 - external parsers, migrations, and rendering may fail
        failure, result = (exc.code if isinstance(exc, ImportFailure) else
                           f"IMPORT_FAILED:{type(exc).__name__}"), "FAILED"
    if failure:
        status = "FAILED"
    warnings = _count_warnings(parsed.warnings if parsed else [])
    if parsed:
        fields = awg_features(parsed)
        enabled = sum(peer.enabled for peer in parsed.peers)
        values = [
            ("mode", status), ("kind", kind), ("name", "[redacted]"), ("listen_port", parsed.listen_port),
            ("address", "[redacted]"), ("mtu", parsed.mtu if parsed.mtu is not None else "-"),
            ("endpoint_host_set", "yes" if parsed.endpoint_host else "no"),
            ("client_dns_count", len(parsed.client_dns or [])),
            ("client_keepalive", parsed.client_keepalive if parsed.client_keepalive is not None else "-"),
            ("awg_features", ",".join(fields["fields"]) or "-"), ("cps_count", fields["cps_count"]),
            ("peers_total", len(parsed.peers)), ("peers_enabled", enabled),
            ("peers_disabled", len(parsed.peers) - enabled),
            ("peers_with_private_key", sum(bool(peer.private_key) for peer in parsed.peers)),
            ("peers_with_psk", sum(bool(peer.preshared_key) for peer in parsed.peers)),
            ("owners_mapped", sum(peer.owner is not None for peer in parsed.peers)),
            ("warnings", ",".join(f"{w.code}={w.count}" for w in warnings) or "-"),
            ("problems", ",".join(f"{p.code}:{p.field}" for p in problems) or "-"),
            ("wg0_verify", verify), ("rendered_state_sha256", checksum),
            ("rendered_peers_in_state", rendered_peers),
            ("result", result if not failure else f"FAILED:{failure}"),
        ]
    else:
        values = [("mode", "FAILED"), ("kind", kind), ("name", "[redacted]"),
                  ("wg0_verify", verify), ("rendered_state_sha256", checksum),
                  ("rendered_peers_in_state", 0), ("result", f"FAILED:{failure or 'IMPORT_FAILED'}")]
    print("\n".join(f"{key}: {value}" for key, value in values), file=out)
    return 2 if failure == "DUPLICATE_INSTANCE" else 1 if failure else 0


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point for offline imports."""
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("amnezia", "wgeasy"))
    parser.add_argument("--source", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verify-wg0")
    parser.add_argument("--bot-db")
    parser.add_argument("--db")
    args = parser.parse_args(argv)
    if args.bot_db and args.kind != "wgeasy":
        parser.error("--bot-db is only valid for wgeasy")
    return run_import(args.kind, args.source, args.name, dry_run=args.dry_run,
                      verify_wg0=args.verify_wg0, bot_db=args.bot_db,
                      db_url=args.db)
