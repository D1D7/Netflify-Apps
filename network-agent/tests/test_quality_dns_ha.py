"""Wi-Fi channel advisor, bufferbloat, service latency, DNS filter, morning summary, Home Assistant MQTT."""

from __future__ import annotations

import asyncio
import json
import struct
from datetime import datetime, timedelta
from types import SimpleNamespace as NS

import dns.message
import dns.rcode
import dns.rrset
import pytest

from netagent.features import dnsfilter, homeassistant as ha, morning, quality
from netagent.state import StateStore

NETSH = """
Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : Biker
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    BSSID 1                 : 28:5b:0c:56:da:2f
         Signal             : 84%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 8
SSID 2 : Sweetvenom
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 60%
         Band               : 2.4 GHz
         Channel            : 6
         Channel Utilization: 30 (11 %)
SSID 3 :
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 40%
         Channel            : 36
"""


# ---------------------------------------------------------------- Wi-Fi
def test_parse_netsh_networks():
    nets = quality.parse_netsh_networks(NETSH)
    assert [n["ssid"] for n in nets] == ["Biker", "Sweetvenom", "(დამალული)"]
    assert nets[0] == {"ssid": "Biker", "bssid": "28:5b:0c:56:da:2f", "signal": 84, "channel": 8, "band": "2.4 GHz", "util": None}
    assert nets[1]["util"] == 11
    assert nets[2]["band"] == "5 GHz"


def test_parse_nmcli():
    nets = quality.parse_nmcli("Home:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:70\n:11\\:22\\:33\\:44\\:55\\:66:44:30\n")
    assert nets[0]["bssid"] == "aa:bb:cc:dd:ee:ff" and nets[0]["channel"] == 6 and nets[0]["signal"] == 70
    assert nets[1]["ssid"] == "(დამალული)" and nets[1]["band"] == "5 GHz"


def test_advise_moves_away_from_crowded_channel():
    nets = quality.parse_netsh_networks(NETSH)
    adv = quality.advise(nets, {"ssid": "Biker", "channel": "8"})
    assert adv["mine"] == ["28:5b:0c:56:da:2f"]
    # neighbour on 6 at 60 % overlaps 8 (distance 2) and sits on 6; channel 1 and 11 are further away
    assert adv["options"][6] > adv["options"][8] > adv["options"][1]
    assert adv["best"] in {1, 11} and adv["gain"] > 0
    text = quality.format_wifi(nets, {"ssid": "Biker", "channel": "8", "signal": "84%", "rx": "144", "band": "2.4 GHz"}, adv, [])
    assert "← შენი" in text and "რჩევა" in text


def test_advise_keeps_good_channel_and_5ghz():
    nets = [{"ssid": "Me", "bssid": "a", "signal": 90, "channel": 1, "band": "2.4 GHz", "util": None}]
    adv = quality.advise(nets, {"ssid": "Me", "channel": "1"})
    assert adv["best"] == 1 and adv["gain"] == 0
    assert quality.advise([], {}) == {"current": 0, "mine": [], "options": {}}
    five = quality.advise([{"ssid": "N", "bssid": "b", "signal": 80, "channel": 36, "band": "5 GHz", "util": None}],
                          {"ssid": "Me", "channel": "36"})
    assert five["best"] != 36


def test_signal_history(tmp_path):
    now = datetime.now()
    quality.record_signal({"ssid": "Biker", "signal": "80%", "channel": "8"}, now - timedelta(hours=30), tmp_path)
    quality.record_signal({"ssid": "Biker", "signal": "70%", "channel": "8"}, now - timedelta(hours=1), tmp_path)
    quality.record_signal({"ssid": "Biker", "signal": "60%", "channel": "8"}, now, tmp_path)
    assert [s for _, s in quality.signal_history(24, tmp_path)] == [70, 60]
    quality.record_signal({"ssid": "x", "signal": "1%"}, now + timedelta(days=20), tmp_path)  # old files are pruned
    assert len(list(tmp_path.glob("*.csv"))) == 1


# ---------------------------------------------------------------- bufferbloat
@pytest.mark.parametrize("inc,g", [(2, "A+"), (20, "A"), (50, "B"), (150, "C"), (300, "D"), (900, "F")])
def test_grades(inc, g):
    assert quality.grade(inc) == g


def test_measure_bufferbloat_with_fake_line():
    busy = {"on": False}

    def load(stop, seconds):
        busy["on"] = True
        stop.wait(seconds)
        busy["on"] = False
        return 50.0

    rtt = lambda: 180.0 if busy["on"] else 10.0  # noqa: E731
    r = quality.measure_bufferbloat(rtt=rtt, load_down=load, load_up=load, seconds=1.2, every=0.05)
    assert r["idle_ms"] == 10.0 and r["down_ms"] == 180.0 and r["grade"] == "C"
    assert "SQM" in quality.format_bufferbloat(r)
    dead = quality.measure_bufferbloat(rtt=lambda: None, load_down=load, load_up=load, seconds=1.0, every=0.05)
    assert dead["grade"] == "?" and "ვერ გაიზომა" in quality.format_bufferbloat(dead)


# ---------------------------------------------------------------- services
def test_services_points_at_the_slow_one():
    def probe(host):
        return {"www.youtube.com": (5, 400.0, ""), "zoom.us": (5, None, "TimeoutError")}.get(host, (5, 30.0, ""))

    rows = quality.check_services(probe)
    assert len(rows) == len(quality.SERVICES)
    text = quality.format_services(rows)
    assert "Zoom: არ პასუხობს" in text and "სხვებზე ბევრად ნელია: YouTube" in text
    ok = quality.format_services(quality.check_services(lambda h: (5, 20.0, "")))
    assert "ყველა სერვისი ნორმალურად" in ok


# ---------------------------------------------------------------- DNS filter
def test_parse_list_formats():
    names = dnsfilter.parse_list("# c\n0.0.0.0 ads.example.com\n127.0.0.1 localhost\n||track.example.net^\nplain.example.org # x\n!adblock\n")
    assert names == {"ads.example.com", "track.example.net", "plain.example.org"}


def test_filter_verdicts(tmp_path):
    st = StateStore(tmp_path / "state.json")
    f = dnsfilter.Filter(st, tmp_path / "dns")
    f.download(fetch=lambda url: "0.0.0.0 doubleclick.net\n0.0.0.0 tracker.example.com\n")
    assert f.verdict("ad.doubleclick.net") == "list" and f.blocked("DoubleClick.NET.")
    assert not f.blocked("google.com")
    dnsfilter._edit(NS(state=st), "allow", add="doubleclick.net")
    assert f.verdict("ad.doubleclick.net") == "allow" and not f.blocked("ad.doubleclick.net")
    dnsfilter._edit(NS(state=st), "block", add="tiktok.com")
    assert f.blocked("www.tiktok.com")
    st.set(dnsfilter.PAUSE_KEY, 9e12)
    assert not f.blocked("www.tiktok.com")
    with pytest.raises(Exception):
        f.download(fetch=lambda url: (_ for _ in ()).throw(OSError("offline")))
    assert f.load() == 2  # the old file is kept when the download fails


def test_lan_client():
    assert dnsfilter.lan_client("192.168.1.5") and dnsfilter.lan_client("127.0.0.1") and dnsfilter.lan_client("fe80::1%3")
    assert not dnsfilter.lan_client("8.8.8.8") and not dnsfilter.lan_client("junk")


def _upstream_answer(wire: bytes) -> bytes:
    q = dns.message.from_wire(wire)
    r = dns.message.make_response(q)

    r.answer.append(dns.rrset.from_text(q.question[0].name, 60, "IN", "A", "93.184.216.34"))
    return r.to_wire()


def test_resolver_end_to_end(tmp_path, monkeypatch):
    st = StateStore(tmp_path / "state.json")
    f = dnsfilter.Filter(st, tmp_path / "dns")
    f.download(fetch=lambda url: "0.0.0.0 ads.example.com\n")
    stats = dnsfilter.Stats()

    async def main():
        loop = asyncio.get_running_loop()

        class Up(asyncio.DatagramProtocol):
            def connection_made(self, tr):
                self.tr = tr

            def datagram_received(self, data, addr):
                self.tr.sendto(_upstream_answer(data), addr)

        up, _ = await loop.create_datagram_endpoint(Up, local_addr=("127.0.0.1", 0))
        port = up.get_extra_info("sockname")[1]
        res = dnsfilter.Resolver(f, stats, upstream=["127.0.0.1"])

        async def udp(wire, server):  # the fake upstream listens on a random port, not 53
            fut = loop.create_future()

            class P(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    fut.set_result(data)

            tr, _ = await loop.create_datagram_endpoint(P, remote_addr=(server, port))
            tr.sendto(wire)
            try:
                return await asyncio.wait_for(fut, 2)
            finally:
                tr.close()

        res._udp = udp
        servers = await dnsfilter.serve(res, "127.0.0.1", 0)
        dport = servers[0].get_extra_info("sockname")[1]

        async def ask(name, rdtype="A", client="127.0.0.1"):
            return dns.message.from_wire(await res.handle(dns.message.make_query(name, rdtype).to_wire(), client))

        good = await ask("www.example.com")
        bad = await ask("x.ads.example.com")
        bad6 = await ask("ads.example.com", "AAAA")
        outsider = await res.handle(dns.message.make_query("a.com", "A").to_wire(), "8.8.8.8")
        garbage = await res.handle(b"\x00\x01", "127.0.0.1")
        # through the real UDP listener as well
        fut = loop.create_future()

        class C(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                fut.set_result(data)

        ctr, _ = await loop.create_datagram_endpoint(C, remote_addr=("127.0.0.1", dport))
        ctr.sendto(dns.message.make_query("ads.example.com", "A").to_wire())
        via_udp = dns.message.from_wire(await asyncio.wait_for(fut, 2))
        ctr.close()
        # an upstream that never answers -> SERVFAIL
        res.upstream, res.timeout = ["127.0.0.1"], 0.2
        res._udp = lambda w, s: asyncio.sleep(1)
        fail = await ask("slow.example.org")
        for x in servers + [up]:
            x.close()
        return good, bad, bad6, outsider, garbage, via_udp, fail

    good, bad, bad6, outsider, garbage, via_udp, fail = asyncio.run(main())
    assert str(good.answer[0][0]) == "93.184.216.34"
    assert str(bad.answer[0][0]) == "0.0.0.0" and str(bad6.answer[0][0]) == "::"
    assert outsider is None and garbage is None
    assert str(via_udp.answer[0][0]) == "0.0.0.0"
    assert fail.rcode() == dns.rcode.SERVFAIL
    d = stats.as_dict()
    assert d["total"] == 5 and d["blocked"] == 3 and d["top_blocked"][0][0] == "ads.example.com"
    st2 = dnsfilter.Stats()
    st2.restore(json.loads(json.dumps(d)))
    assert st2.as_dict()["blocked"] == 3


def test_dns_command(tmp_path, monkeypatch):
    st = StateStore(tmp_path / "state.json")
    s = NS(state=st)
    monkeypatch.setattr(dnsfilter, "FILTER", dnsfilter.Filter(st, tmp_path / "dns"))
    monkeypatch.setattr(dnsfilter, "RUNNING", {})
    monkeypatch.delenv("NETAGENT_DNS", raising=False)
    assert "გამორთულია" in dnsfilter.dns_cmd(s, [], None).text
    assert "დაიბლოკება" in dnsfilter.dns_cmd(s, ["block", "https://Ads.Example.com/x"], None).text
    assert "შენი ბლოკ-სია" in dnsfilter.dns_cmd(s, ["test", "a.ads.example.com"], None).text
    assert "ყოველთვის დაშვებულია" in dnsfilter.dns_cmd(s, ["allow", "ads.example.com"], None).text
    assert st.get(dnsfilter.LISTS_KEY) == {"block": [], "allow": ["ads.example.com"]}
    assert "შეჩერდა 5" in dnsfilter.dns_cmd(s, ["pause", "5"], None).text
    with pytest.raises(Exception):
        dnsfilter.dns_cmd(s, ["block", "notadomain"], None)
    monkeypatch.setenv("NETAGENT_DNS", "on")
    monkeypatch.setattr(dnsfilter, "FAILED", {"error": "0.0.0.0:53 — in use"})
    assert "SharedAccess" in dnsfilter.dns_cmd(s, [], None).text


# ---------------------------------------------------------------- morning summary
def test_morning_due():
    at = (8, 0)
    d = datetime(2026, 11, 9, 8, 1)
    assert morning.due(d, at, None) and morning.due(d, at, "2026-11-08")
    assert not morning.due(d, at, "2026-11-09")
    assert not morning.due(datetime(2026, 11, 9, 7, 59), at, None)
    assert morning.due(datetime(2026, 11, 9, 10, 30), at, None)          # PC woke up late
    assert not morning.due(datetime(2026, 11, 9, 13, 0), at, None)       # too late, skip that day
    assert not morning.due(d, None, None)


def test_morning_build(tmp_path, monkeypatch):
    st = StateStore(tmp_path / "state.json")
    st.set("isp_speedtests", [{"ts": "2026-11-09T07:00:00", "down_mbps": 50.0, "up_mbps": 70.0}])
    st.set("bufferbloat_tests", [{"grade": "A"}])
    s = NS(state=st)
    import netagent.features.isp as isp

    monkeypatch.setattr(isp, "monitor_for", lambda s: NS(summary=lambda d: {
        "samples": 100, "outages": [{"seconds": 120}], "outage_total_seconds": 120, "latency_avg_ms": 9.5,
        "uptime_percent": 99.7, "down_now_since": None}))
    monkeypatch.setattr(quality, "signal_history", lambda h: [(None, 80), (None, 60)])
    now = __import__("time").time()
    live = NS(snapshot=lambda: {"online": 5, "devices": [
        {"online": True, "trusted": False, "self": False, "label": "", "hostname": "", "vendor": "Xiaomi", "ip": "192.168.1.50"},
        {"online": True, "trusted": True, "self": False, "label": "TV", "hostname": "", "vendor": "", "ip": "192.168.1.2"}]},
        events=[{"event": "new", "ts": now - 3600, "hostname": "", "vendor": "Xiaomi", "ip": "192.168.1.50"}])
    text = morning.build(s, live=live)
    assert "1 გათიშვა, ჯამში 2 წთ" in text and "ping საშუალოდ 9.5" in text
    assert "ჩამოტვირთვა (download) 50.0 Mbps" in text and "Bufferbloat" in text
    assert "ახლა: **5**" in text and "1 ახალი: Xiaomi" in text and "1 უცნობი: Xiaomi" in text
    assert "საშუალოდ 70%" in text
    assert "⬇" not in text and "⬆" not in text


# ---------------------------------------------------------------- Home Assistant MQTT
def test_mqtt_packets():
    assert ha._len(0) == b"\x00" and ha._len(127) == b"\x7f" and ha._len(128) == b"\x80\x01" and ha._len(16384) == b"\x80\x80\x01"
    c = ha.connect_packet("cid", "user", "pw")
    assert c[0] == 0x10 and c[2:8] == b"\x00\x04MQTT" and c[8] == 4 and c[9] == 0xC2
    p = ha.publish_packet("a/b", "x" * 200)
    assert p[0] == 0x31 and p[1:3] == ha._len(205)


def test_config(monkeypatch):
    monkeypatch.setenv("NETAGENT_MQTT", "192.168.1.10:1884")
    assert ha.config()["host"] == "192.168.1.10" and ha.config()["port"] == 1884
    monkeypatch.setenv("NETAGENT_MQTT", "ha.local")
    assert ha.config()["port"] == 1883
    monkeypatch.setenv("NETAGENT_MQTT", "off")
    assert ha.config() is None


async def _fake_broker(received: list, rc: int = 0):
    async def on_client(reader, writer):
        def remaining():
            async def read():
                mult, n = 1, 0
                while True:
                    b = (await reader.readexactly(1))[0]
                    n += (b & 0x7F) * mult
                    mult *= 128
                    if not b & 0x80:
                        return n
            return read()

        try:
            while True:
                head = (await reader.readexactly(1))[0]
                body = await reader.readexactly(await remaining())
                if head == 0x10:
                    received.append(("connect", body))
                    writer.write(bytes([0x20, 2, 0, rc]))
                    await writer.drain()
                elif head & 0xF0 == 0x30:
                    n = struct.unpack("!H", body[:2])[0]
                    received.append((body[2:2 + n].decode(), body[2 + n:].decode(), bool(head & 1)))
                elif head == 0xE0:
                    received.append(("disconnect",))
                    break
        except asyncio.IncompleteReadError:
            pass
        writer.close()

    return await asyncio.start_server(on_client, "127.0.0.1", 0)


def test_publish_discovery_to_broker(monkeypatch):
    values = {"internet": True, "ping_ms": 9.1, "download_mbps": 50.0, "upload_mbps": 70.0, "devices_online": 7,
              "unknown_devices": 1, "devices": {"tv": {"name": "TV", "home": True, "ip": "192.168.1.2"}}}

    async def main(rc=0):
        got = []
        srv = await _fake_broker(got, rc)
        port = srv.sockets[0].getsockname()[1]
        cfg = {"host": "127.0.0.1", "port": port, "user": "u", "password": "p", "prefix": "homeassistant"}
        try:
            n = await ha.publish_all(cfg, ha.messages(cfg, values))
        finally:
            await asyncio.sleep(0.1)
            srv.close()
        return n, got

    n, got = asyncio.run(main())
    pubs = [g for g in got if len(g) == 3]
    assert got[0][0] == "connect" and got[-1] == ("disconnect",) and n == len(pubs)
    topics = {t: (json.loads(p) if p.startswith("{") else p) for t, p, _ in pubs}
    node = ha.NODE
    ping = topics[f"homeassistant/sensor/netagent_{node}/ping_ms/config"]
    assert ping["unit_of_measurement"] == "ms" and ping["expire_after"] == 300 and ping["device"]["name"].startswith("NetAgent")
    assert topics[f"homeassistant/binary_sensor/netagent_{node}/internet/config"]["device_class"] == "connectivity"
    assert topics[f"homeassistant/binary_sensor/netagent_{node}/home_tv/config"]["device_class"] == "presence"
    assert topics[f"netagent/{node}/home/tv"] == "ON"
    state = topics[f"netagent/{node}/state"]
    assert state["internet"] == "ON" and state["devices_online"] == 7 and state["wifi_signal"] is None
    assert all(r for _, _, r in pubs)  # retained, so HA gets them after its own restart

    with pytest.raises(Exception, match="მომხმარებელი/პაროლი"):
        asyncio.run(main(rc=4))
