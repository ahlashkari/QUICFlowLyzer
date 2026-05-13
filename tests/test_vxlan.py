import dpkt

from vxlan import try_decap_vxlan, VXLAN_DEFAULT_PORT


def build_eth_ip_udp(payload: bytes, sport: int = 12345, dport: int = VXLAN_DEFAULT_PORT, v6: bool = False) -> dpkt.ethernet.Ethernet:
    eth = dpkt.ethernet.Ethernet()
    eth.src = b"\x00\x01\x02\x03\x04\x05"
    eth.dst = b"\x06\x07\x08\t\n\x0b"
    if not v6:
        ip = dpkt.ip.IP()
        ip.p = dpkt.ip.IP_PROTO_UDP
        ip.src = b"\x0a\x00\x00\x01"  # 10.0.0.1
        ip.dst = b"\x0a\x00\x00\x02"  # 10.0.0.2
    else:
        ip = dpkt.ip6.IP6()
        ip.nxt = dpkt.ip.IP_PROTO_UDP
        ip.src = b"\x20\x01" + b"\x00" * 14
        ip.dst = b"\x20\x01" + b"\x00" * 14
    udp = dpkt.udp.UDP()
    udp.sport = sport
    udp.dport = dport
    udp.data = payload
    udp.ulen = len(udp.data) + 8
    # dpkt requires packing lengths via .pack() or setting sum fields; Ethernet will pack recursively
    ip.data = udp
    eth.data = ip
    return eth


def build_vxlan_payload(vni: int, inner_eth_bytes: bytes, set_instance_flag: bool = True) -> bytes:
    header = bytearray(8)
    # Flags: I-flag bit (0x08) optionally set
    header[0] = 0x08 if set_instance_flag else 0x00
    # VNI at bytes 4..6
    header[4] = (vni >> 16) & 0xFF
    header[5] = (vni >> 8) & 0xFF
    header[6] = vni & 0xFF
    return bytes(header) + inner_eth_bytes


def minimal_inner_eth(payload_len: int = 0) -> bytes:
    # 14-byte Ethernet header + optional payload
    return b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x00\x11\x22\x33\x44\x55" + b"\x08\x00" + (b"X" * payload_len)


def test_non_ip_returns_original():
    eth = dpkt.ethernet.Ethernet()
    eth.data = b"raw"
    res = try_decap_vxlan(eth)
    assert res.eth is eth
    assert not res.decapsulated


def test_ip_non_udp_returns_original():
    eth = dpkt.ethernet.Ethernet()
    ip = dpkt.ip.IP()
    ip.p = dpkt.ip.IP_PROTO_TCP
    eth.data = ip
    res = try_decap_vxlan(eth)
    assert res.eth is eth
    assert not res.decapsulated


def test_udp_wrong_port_returns_original():
    inner = minimal_inner_eth()
    payload = build_vxlan_payload(1, inner)
    eth = build_eth_ip_udp(payload, dport=9999)
    res = try_decap_vxlan(eth)
    assert res.eth is eth
    assert not res.decapsulated


def test_vxlan_header_too_short():
    eth = build_eth_ip_udp(b"\x00" * 7)
    res = try_decap_vxlan(eth)
    assert not res.decapsulated
    assert res.eth is eth


def test_valid_vxlan_min_inner():
    inner = minimal_inner_eth()
    payload = build_vxlan_payload(0x123456, inner)
    eth = build_eth_ip_udp(payload)
    res = try_decap_vxlan(eth)
    assert res.decapsulated
    assert res.vni == 0x123456
    assert isinstance(res.eth, dpkt.ethernet.Ethernet)


def test_inner_too_short():
    inner = minimal_inner_eth()[:13]
    payload = build_vxlan_payload(1, inner)
    eth = build_eth_ip_udp(payload)
    res = try_decap_vxlan(eth)
    assert not res.decapsulated
    assert res.eth is eth


def test_allowed_outer_ips_policy():
    inner = minimal_inner_eth()
    payload = build_vxlan_payload(1, inner)
    eth = build_eth_ip_udp(payload)
    # IPs used: 10.0.0.1 -> 10.0.0.2
    res_block = try_decap_vxlan(eth, allowed_outer_ips={"1.1.1.1"})
    assert not res_block.decapsulated
    res_pass = try_decap_vxlan(eth, allowed_outer_ips={"10.0.0.1"})
    assert res_pass.decapsulated


def test_allowed_inner_cidrs_policy_ipv4():
    # Inner IPv4 frame
    inner_ip = dpkt.ip.IP()
    inner_ip.src = b"\x0a\x01\x02\x03"
    inner_ip.dst = b"\x0a\xff\x00\x01"
    inner_ip.p = dpkt.ip.IP_PROTO_TCP
    inner_eth = dpkt.ethernet.Ethernet()
    inner_eth.src = b"\xaa\xbb\xcc\xdd\xee\xff"
    inner_eth.dst = b"\x00\x11\x22\x33\x44\x55"
    inner_eth.data = inner_ip
    payload = build_vxlan_payload(1, bytes(inner_eth))
    eth = build_eth_ip_udp(payload)
    res_block = try_decap_vxlan(eth, allowed_inner_cidrs=["192.168.0.0/16"])  # no match
    assert not res_block.decapsulated
    res_pass = try_decap_vxlan(eth, allowed_inner_cidrs=["10.0.0.0/8"])  # match
    assert res_pass.decapsulated


def test_instance_flag_required_and_optional():
    inner = minimal_inner_eth()
    # Without I-flag
    payload_no_i = build_vxlan_payload(1, inner, set_instance_flag=False)
    eth_no_i = build_eth_ip_udp(payload_no_i)
    res_required = try_decap_vxlan(eth_no_i, require_instance_flag=True)
    assert not res_required.decapsulated
    res_optional = try_decap_vxlan(eth_no_i, require_instance_flag=False)
    assert res_optional.decapsulated


def test_mirrored_sport_allowed():
    inner = minimal_inner_eth()
    payload = build_vxlan_payload(1, inner)
    eth = build_eth_ip_udp(payload, sport=VXLAN_DEFAULT_PORT, dport=12345)
    res = try_decap_vxlan(eth, allow_mirrored_sport=True)
    assert res.decapsulated


def test_nested_vxlan_depth_and_limit():
    inner_leaf = minimal_inner_eth()
    # Layer 1 (innermost) VXLAN payload
    l1_payload = build_vxlan_payload(0x1, inner_leaf)
    l1_eth = build_eth_ip_udp(l1_payload)
    # Layer 2 encapsulating Layer 1 ethernet as inner bytes
    l2_payload = build_vxlan_payload(0x2, bytes(l1_eth))
    l2_eth = build_eth_ip_udp(l2_payload)

    res_two = try_decap_vxlan(l2_eth, max_layers=2)
    assert res_two.decapsulated
    assert res_two.layers_stripped == 2

    res_limit = try_decap_vxlan(l2_eth, max_layers=1)
    assert res_limit.decapsulated
    assert res_limit.layers_stripped == 1


def test_corrupted_inner_safe_fallback():
    # Build valid header but corrupt inner so dpkt cannot parse
    inner = b"\x00" * 14  # Ethernet header bytes but bogus type may still parse; use shorter to force fail
    payload = build_vxlan_payload(1, inner[:10])  # too short for Ethernet
    eth = build_eth_ip_udp(payload)
    res = try_decap_vxlan(eth)
    assert not res.decapsulated

