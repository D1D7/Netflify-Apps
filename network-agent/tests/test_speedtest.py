"""Speed test math against a simulated connection (fake clock): ping median, time-limited download, sized upload."""

from __future__ import annotations

import pytest

from netagent.features import isp


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class Resp:
    def __init__(self, data=None, headers=None, chunks=None, clock=None, rate=None):
        self._data, self.headers, self._chunks, self._clock, self._rate = data, headers or {}, chunks or [], clock, rate

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data

    def iter_bytes(self):
        for n in self._chunks:
            self._clock.t += n * 8 / self._rate
            yield b"x" * n

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeLink:
    """A line with given download/upload Mbps, base RTT and a latency spike on some requests."""

    def __init__(self, clock, down=20.0, up=80.0, rtt_ms=25.0, spikes=(2, 5), spike_ms=400.0, meta=True):
        self.clock, self.down, self.up, self.rtt, self.spikes, self.spike, self.meta = clock, down, up, rtt_ms, spikes, spike_ms, meta
        self.pings = 0
        self.posts = []

    def rtt_sample(self):
        extra = self.spike if self.pings in self.spikes else 0.0
        self.pings += 1
        return self.rtt + extra

    def get(self, url, timeout=None):
        if url.endswith("/meta"):
            return Resp({"asOrganization": "Silknet", "clientIp": "1.2.3.4", "city": "Tbilisi"} if self.meta else None)
        extra = self.spike if self.pings in self.spikes else 0.0
        self.pings += 1
        self.clock.t += (self.rtt + extra + 2) / 1000  # 2 ms of server time, reported in Server-Timing
        return Resp(headers={"server-timing": "cfRequestDuration;dur=2.0"})

    def stream(self, method, url):
        total = int(url.split("bytes=")[1])
        self.clock.t += self.rtt / 1000  # time to first byte: latency, must not count as bandwidth
        return Resp(chunks=[65536] * (total // 65536), clock=self.clock, rate=self.down * 1e6)

    def post(self, url, content):
        self.posts.append(len(content))
        self.clock.t += self.rtt / 1000 + len(content) * 8 / (self.up * 1e6)
        return Resp(headers={})


def test_measure_matches_the_line():
    clock = Clock()
    link = FakeLink(clock, down=20.0, up=80.0)
    r = isp.measure_speed(link, clock, rtt=link.rtt_sample)
    assert r["down_mbps"] == pytest.approx(20.0, rel=0.02)
    assert r["up_mbps"] == pytest.approx(80.0, rel=0.03)
    assert r["ping_ms"] == pytest.approx(25.0, abs=0.5)  # spikes of 400 ms do not move the median
    assert r["jitter_ms"] > 50  # but they show up as jitter
    assert (r["isp"], r["city"]) == ("Silknet", "Tbilisi")


def test_slow_download_stops_in_time():
    clock = Clock()
    link = FakeLink(clock, down=3.0, up=75.0, spikes=())
    t0 = clock.t
    r = isp.measure_speed(link, clock, rtt=link.rtt_sample)
    assert r["down_mbps"] == pytest.approx(3.0, rel=0.03)
    download_s = (3.0 * 1e6 / 8 * isp.DOWN_SECONDS) * 8 / 3e6
    assert clock.t - t0 < download_s + 15  # ~8 s download + ~5 s upload, not the 133 s of a full 50 MB
    assert r["jitter_ms"] == pytest.approx(0, abs=0.01)


def test_upload_size_follows_the_line():
    clock = Clock()
    fast = FakeLink(clock, up=200.0)
    isp.measure_speed(fast, clock, rtt=fast.rtt_sample)
    assert fast.posts[0] == isp.UP_PROBE_BYTES and fast.posts[1] == isp.UP_MAX_BYTES  # capped
    slow = FakeLink(clock, up=1.0)
    isp.measure_speed(slow, clock, rtt=slow.rtt_sample)
    assert slow.posts[1] == isp.UP_PROBE_BYTES  # 5 s at 1 Mbps is less than the probe: clamped up to it


def test_missing_meta_is_fine():
    clock = Clock()
    link = FakeLink(clock, meta=False)
    r = isp.measure_speed(link, clock, rtt=link.rtt_sample)
    assert r["isp"] == "" and r["down_mbps"] > 0


def test_server_timing_parser():
    assert isp._server_ms({"server-timing": "cfRequestDuration;dur=12.5"}) == 12.5  # noqa: SLF001
    assert isp._server_ms({"server-timing": "cache;desc=hit, cfRequestDuration;dur=3"}) == 3.0  # noqa: SLF001
    assert isp._server_ms({}) == 0.0  # noqa: SLF001


def test_format_speed_warnings():
    text = isp.format_speed({"down_mbps": 3.3, "up_mbps": 75.0, "ping_ms": 28.0, "jitter_ms": 120.0,
                             "isp": "Silknet", "city": "Tbilisi"})
    assert "ჩამოტვირთვა (download): **3.3** Mbps" in text and "რყევა ±120 ms" in text
    assert "ატვირთვაზე ბევრად ნელია" in text and "არასტაბილურია" in text and "Silknet, Tbilisi" in text
    calm = isp.format_speed({"down_mbps": 90.0, "up_mbps": 40.0, "ping_ms": 12.0, "jitter_ms": 0.4})
    assert "⚠️" not in calm and "რყევა" not in calm and "პროვაიდერი" not in calm


def test_ping_unmeasurable():
    clock = Clock()
    link = FakeLink(clock)
    r = isp.measure_speed(link, clock, rtt=lambda: None)
    assert r["ping_ms"] is None and r["jitter_ms"] == 0.0
    assert "ვერ გაიზომა" in isp.format_speed(r)


def test_upload_failure_keeps_download_and_ping():
    """A timeout in the upload part used to throw the whole measurement away (seen in the real log)."""
    import httpx

    from netagent.features import isp

    class C:
        def get(self, url, timeout=None):
            raise httpx.ConnectError("meta down")

        def stream(self, method, url):
            class R:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

                def iter_bytes(self):
                    for _ in range(5):
                        yield b"x" * 1_000_000

            return R()

        def post(self, url, content=None):
            raise httpx.ReadTimeout("upload stalled")

    ticks = iter(range(0, 1000))
    m = isp.measure_speed(C(), clock=lambda: next(ticks) * 0.1, rtt=lambda: 7.0)
    assert m["down_mbps"] > 0 and m["ping_ms"] == 7.0 and m["up_mbps"] is None and m["up_error"] == "ReadTimeout"
    text = isp.format_speed({"ts": "2026-11-11T22:35:00", **m})
    assert "ვერ გაიზომა" in text and "None" not in text
    st = isp.speed_stats([{"ts": "a", "down_mbps": 10.0, "up_mbps": None}, {"ts": "b", "down_mbps": 20.0, "up_mbps": 30.0}])
    assert st["up_avg"] == 30.0 and st["down_avg"] == 15.0
    st = isp.speed_stats([{"ts": "a", "down_mbps": 10.0, "up_mbps": None}])
    assert st["up_avg"] is None and "—" in isp.format_speed_history(st, 7)
