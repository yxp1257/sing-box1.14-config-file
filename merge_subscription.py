#!/usr/bin/env python3
"""
merge_subscription.py

Fetches a subscription link (base64-encoded list of vless:// / vmess:// /
trojan:// URIs), parses the nodes, and rebuilds a sing-box config.json from
a fixed template (sing_box_template.json in the same folder).

Usage:
    python3 merge_subscription.py --url "https://your-sub-link/sub"

Re-run this any time your subscription's nodes change - the DNS / route /
tun sections never need to be touched again, only the node list.
"""

import argparse
import base64
import json
import re
import sys
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote

NODE_GROUP_TAGS = {"🚀 节点选择", "♻️ 自动选择", "🔯 故障转移", "🔮 负载均衡"}
# Preference order when the same node name appears in multiple protocols
# (e.g. this sub gives vless/vmess/trojan for the same server) - only the
# first-seen protocol per tag is kept.
PROTOCOL_PREFERENCE = ["vless", "trojan", "vmess", "hysteria2", "hysteria", "tuic", "shadowsocks"]


def fetch_subscription(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "sing-box"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw = resp.read()
    text = raw.decode("utf-8", errors="ignore").strip()
    # Subscriptions are usually base64 of the whole node list. If it doesn't
    # look like a URI list already, try to base64-decode it.
    if not re.search(r"^(vless|vmess|trojan|ss|hysteria2?|tuic)://", text, re.MULTILINE):
        padded = text + "=" * (-len(text) % 4)
        try:
            text = base64.b64decode(padded).decode("utf-8", errors="ignore")
        except Exception as e:
            print(f"warning: base64 decode failed ({e}), using raw content", file=sys.stderr)
    return text


def b64_decode_flexible(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    if "-" in s or "_" in s:
        return base64.urlsafe_b64decode(s.encode())
    return base64.b64decode(s.encode())


def split_early_data(path: str):
    """Cloudflare-Worker-style vless/vmess/trojan links encode WebSocket
    0-RTT 'early data' as a `?ed=<bytes>` query param on the path (a v2ray/
    xray convention). sing-box doesn't understand that query param at all -
    it needs the same thing expressed as two separate transport fields
    (max_early_data / early_data_header_name). Split it out here."""
    if "?ed=" in path:
        base, _, query = path.partition("?")
        m = re.search(r"(?:^|&)ed=(\d+)", query)
        if m:
            return base or "/", int(m.group(1))
    return path, None


def apply_early_data(transport: dict, path: str):
    base_path, ed = split_early_data(path)
    transport["path"] = base_path
    if ed:
        transport["max_early_data"] = ed
        transport["early_data_header_name"] = "Sec-WebSocket-Protocol"


def parse_vless(uri: str):
    u = urlparse(uri)
    q = parse_qs(u.query)
    server, port = u.hostname, u.port
    tag = unquote(u.fragment) or f"vless-{server}"
    security = q.get("security", ["none"])[0]
    net = q.get("type", ["tcp"])[0]

    ob = {
        "type": "vless",
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": u.username,
    }
    flow = q.get("flow", [None])[0]
    if flow:
        ob["flow"] = flow

    if net == "ws":
        transport = {"type": "ws", "headers": {"Host": q.get("host", [server])[0]}}
        apply_early_data(transport, q.get("path", ["/"])[0])
        ob["transport"] = transport
    elif net == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": q.get("serviceName", [""])[0]}

    if security == "tls":
        ob["tls"] = {"enabled": True, "server_name": q.get("sni", [server])[0], "insecure": True}
        fp = q.get("fp", [None])[0]
        if fp:
            ob["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
    elif security == "reality":
        ob["tls"] = {
            "enabled": True,
            "server_name": q.get("sni", [server])[0],
            "reality": {
                "enabled": True,
                "public_key": q.get("pbk", [""])[0],
                "short_id": q.get("sid", [""])[0],
            },
        }
        fp = q.get("fp", [None])[0]
        if fp:
            ob["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
    return ob, tag


def parse_vmess(uri: str):
    payload = uri[len("vmess://"):]
    data = json.loads(b64_decode_flexible(payload))
    server = data["add"]
    tag = data.get("ps") or f"vmess-{server}"
    ob = {
        "type": "vmess",
        "tag": tag,
        "server": server,
        "server_port": int(data["port"]),
        "uuid": data["id"],
        "security": data.get("scy", "auto"),
        "alter_id": int(data.get("aid", 0)),
    }
    net = data.get("net", "tcp")
    if net == "ws":
        transport = {"type": "ws", "headers": {"Host": data.get("host", server)}}
        apply_early_data(transport, data.get("path", "/"))
        ob["transport"] = transport
    elif net == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": data.get("path", "")}

    if data.get("tls") == "tls":
        ob["tls"] = {
            "enabled": True,
            "server_name": data.get("sni") or data.get("host") or server,
            "insecure": True,
        }
        fp = data.get("fp")
        if fp:
            ob["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
    return ob, tag


def parse_trojan(uri: str):
    u = urlparse(uri)
    q = parse_qs(u.query)
    server, port = u.hostname, u.port
    tag = unquote(u.fragment) or f"trojan-{server}"
    ob = {
        "type": "trojan",
        "tag": tag,
        "server": server,
        "server_port": port,
        "password": u.username,
    }
    if q.get("type", ["tcp"])[0] == "ws":
        transport = {"type": "ws", "headers": {"Host": q.get("host", [server])[0]}}
        apply_early_data(transport, q.get("path", ["/"])[0])
        ob["transport"] = transport
    if q.get("security", ["tls"])[0] == "tls":
        ob["tls"] = {"enabled": True, "server_name": q.get("sni", [server])[0], "insecure": True}
        fp = q.get("fp", [None])[0]
        if fp:
            ob["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
    return ob, tag


def parse_hysteria2(uri: str):
    u = urlparse(uri)
    q = parse_qs(u.query)
    server, port = u.hostname, u.port
    tag = unquote(u.fragment) or f"hy2-{server}"
    ob = {
        "type": "hysteria2",
        "tag": tag,
        "server": server,
        "server_port": port,
        "password": u.username,
        "tls": {"enabled": True, "server_name": q.get("sni", [server])[0], "insecure": True},
    }
    return ob, tag


PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
}


def scheme_of(line: str) -> str:
    return line.split("://", 1)[0].lower()


def parse_nodes(text: str):
    """Parse subscription text into a list of (protocol, tag, outbound_dict),
    keeping only one protocol per unique tag (preference order above)."""
    by_tag = {}
    for line in text.splitlines():
        line = line.strip()
        if "://" not in line:
            continue
        scheme = scheme_of(line)
        parser = PARSERS.get(scheme)
        if not parser:
            continue
        try:
            ob, tag = parser(line)
        except Exception as e:
            print(f"warning: failed to parse a {scheme} line ({e}), skipping", file=sys.stderr)
            continue

        if tag not in by_tag:
            by_tag[tag] = (scheme, ob)
        else:
            existing_scheme, _ = by_tag[tag]
            if PROTOCOL_PREFERENCE.index(scheme) < PROTOCOL_PREFERENCE.index(existing_scheme):
                by_tag[tag] = (scheme, ob)

    # de-dupe tag collisions between genuinely different servers
    seen_tags = {}
    result = []
    for tag, (scheme, ob) in by_tag.items():
        final_tag = tag
        n = 2
        while final_tag in seen_tags:
            final_tag = f"{tag} ({n})"
            n += 1
        seen_tags[final_tag] = True
        ob["tag"] = final_tag
        result.append(ob)
    return result


PROXY_OUTBOUND_TYPES = {
    "vless", "vmess", "trojan", "shadowsocks", "hysteria2", "hysteria", "tuic", "wireguard",
}


def build_config(template_path: str, nodes: list) -> dict:
    with open(template_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    node_tags = [n["tag"] for n in nodes]

    # Always strip any real proxy nodes already present in the template first.
    # This makes the script safe even if you accidentally point --template at
    # an old, already-populated config.json instead of the clean template -
    # stale nodes from a previous subscription can never leak through.
    non_proxy_outbounds = [o for o in config["outbounds"] if o.get("type") not in PROXY_OUTBOUND_TYPES]
    config["outbounds"] = non_proxy_outbounds

    # Insert the fresh node outbounds right after REJECT (before the selector groups)
    insert_at = next(i for i, o in enumerate(config["outbounds"]) if o.get("tag") == "REJECT") + 1
    config["outbounds"][insert_at:insert_at] = nodes

    # Populate the node-group selectors with ONLY the fresh node list (never
    # merged/appended with whatever was there before)
    for o in config["outbounds"]:
        tag = o.get("tag")
        if tag == "🚀 节点选择":
            o["outbounds"] = ["♻️ 自动选择", "🔯 故障转移", "🔮 负载均衡", "DIRECT"] + node_tags
        elif tag in NODE_GROUP_TAGS:
            o["outbounds"] = list(node_tags)

    # Final safety pass: some templates hardcode individual node names directly
    # into other selectors (e.g. "🐟 漏网之鱼" listing every real node alongside
    # the meta-groups). Since old nodes were stripped above, any such reference
    # is now a dangling pointer to a tag that no longer exists - sing-box will
    # refuse to start with "dependency[...] not found". Scrub every selector's
    # outbounds list down to only tags that actually exist in this config.
    valid_tags = {o.get("tag") for o in config["outbounds"] if o.get("tag")}
    for o in config["outbounds"]:
        if "outbounds" in o:
            o["outbounds"] = [t for t in o["outbounds"] if t in valid_tags]

    return config


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="Subscription URL")
    ap.add_argument("--template", default="sing_box_template.json")
    ap.add_argument("--output", default="config.json")
    args = ap.parse_args()

    print(f"Fetching {args.url} ...")
    text = fetch_subscription(args.url)
    nodes = parse_nodes(text)
    if not nodes:
        print("error: no nodes parsed from subscription - check the URL/format", file=sys.stderr)
        sys.exit(1)
    print(f"Parsed {len(nodes)} node(s):")
    for n in nodes:
        print(f"  - [{n['type']}] {n['tag']} -> {n['server']}:{n['server_port']}")

    config = build_config(args.template, nodes)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
