"""Unit tests for the deterministic anomaly detectors."""
from __future__ import annotations

from datetime import datetime, timezone

from tests.conftest import entries_at, entry

from app.detectors import engine
from app.detectors import (
    MAX_FINDINGS,
    detect_blocked_spike,
    detect_byte_volume,
    detect_cloud_upload,
    detect_host_sweep,
    detect_ip_burst,
    detect_off_hours,
    detect_rare_user_agent,
    detect_tool_download,
    run_detectors,
    severity_for,
    top_findings,
)
from app.detectors.ip_burst import BURST_WINDOW_SECONDS, MIN_BURST_COUNT

NIGHT = datetime(2026, 7, 14, 2, 14, tzinfo=timezone.utc)  # Tuesday, 02:14 UTC
SATURDAY_MIDDAY = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)


# --- severity banding ---------------------------------------------------------


def test_severity_bands_map_confidence_to_labels():
    assert severity_for(0.1) == "low"
    assert severity_for(0.5) == "medium"
    assert severity_for(0.8) == "high"
    assert severity_for(0.95) == "critical"


def test_severity_bands_are_exclusive_at_their_boundaries():
    """The bounds are the part that silently drifts, so pin them exactly."""
    assert severity_for(0.0) == "low"
    assert severity_for(0.4) == "medium"
    assert severity_for(0.7) == "high"
    assert severity_for(0.9) == "critical"
    assert severity_for(1.0) == "critical"


# --- ip burst -----------------------------------------------------------------


def test_ip_burst_flags_requests_packed_into_one_window():
    findings = detect_ip_burst(entries_at([0, 1, 2, 3, 4, 5]))

    assert len(findings) == 1
    assert findings[0].type == "ip_burst"
    assert findings[0].confidence > 0
    assert "6 requests" in findings[0].reason


def test_ip_burst_ignores_traffic_spread_beyond_the_window():
    spread = [i * (BURST_WINDOW_SECONDS + 1) for i in range(MIN_BURST_COUNT * 2)]

    assert detect_ip_burst(entries_at(spread)) == []


def test_ip_burst_scores_a_denser_burst_higher():
    light = detect_ip_burst(entries_at([0, 1, 2, 3, 4]))[0]
    heavy = detect_ip_burst(entries_at(list(range(10))))[0]

    assert heavy.confidence > light.confidence
    assert heavy.severity == "critical"


def test_ip_burst_tracks_each_ip_separately():
    mixed = entries_at([0, 1, 2, 3, 4, 5], src_ip="10.0.0.1") + entries_at(
        [0, 1], src_ip="10.0.0.2"
    )
    findings = detect_ip_burst(mixed)

    assert len(findings) == 1
    assert "10.0.0.1" in findings[0].reason


def test_ip_burst_skips_entries_without_a_timestamp():
    assert detect_ip_burst([entry(ts=None) for _ in range(10)]) == []


def test_ip_burst_anchors_the_finding_to_the_entry_opening_the_burst():
    burst = entries_at([0, 1, 2, 3, 4, 5])

    assert detect_ip_burst(burst)[0].entry_id == burst[0].id


# --- blocked spike ------------------------------------------------------------


def test_blocked_spike_flags_an_ip_mostly_refused_by_the_proxy():
    blocked = entries_at([0, 60, 120, 180], action="Blocked", status_code=403)
    findings = detect_blocked_spike(blocked + entries_at([240]))

    assert len(findings) == 1
    assert findings[0].type == "blocked_spike"
    assert "4 of 5" in findings[0].reason


def test_blocked_spike_ignores_an_occasional_block():
    blocked = entries_at([0, 60], action="Blocked", status_code=403)
    allowed = entries_at([120, 180, 240, 300, 360, 420])

    assert detect_blocked_spike(blocked + allowed) == []


def test_blocked_spike_reads_the_status_code_when_the_action_is_absent():
    denied = entries_at([0, 60, 120], action=None, status_code=401)

    assert len(detect_blocked_spike(denied)) == 1


def test_blocked_spike_scores_a_higher_block_ratio_higher():
    mostly = entries_at([0, 60, 120, 180], action="Blocked") + entries_at([240, 300])
    entirely = entries_at([0, 60, 120, 180], action="Blocked")

    assert detect_blocked_spike(entirely)[0].confidence > detect_blocked_spike(mostly)[0].confidence


# --- rare user agent ----------------------------------------------------------


def test_rare_user_agent_flags_exploitation_tooling_above_generic_automation():
    sqlmap = detect_rare_user_agent([entry(user_agent="sqlmap/1.8")])[0]
    curl = detect_rare_user_agent([entry(user_agent="curl/8.4.0")])[0]

    assert sqlmap.severity == "high"
    assert curl.confidence < sqlmap.confidence
    assert "tool signature" in curl.reason


def test_rare_user_agent_ignores_ordinary_browsers():
    assert detect_rare_user_agent(entries_at([0, 60, 120])) == []


def test_rare_user_agent_needs_a_population_before_trusting_rarity():
    """In a small file every agent is 'rare', so rarity alone must not fire."""
    crowd = entries_at(list(range(20)), user_agent="Mozilla/5.0 Chrome/126.0")
    odd_one_out = [entry(user_agent="Mozilla/5.0 Firefox/128.0")]

    assert detect_rare_user_agent(crowd + odd_one_out) == []


def test_rare_user_agent_flags_a_minority_agent_in_a_large_file():
    crowd = entries_at(list(range(100)), user_agent="Mozilla/5.0 Chrome/126.0")
    odd_one_out = [entry(user_agent="Mozilla/5.0 Firefox/128.0")]

    findings = detect_rare_user_agent(crowd + odd_one_out)

    assert len(findings) == 1
    assert findings[0].entry_id == odd_one_out[0].id
    assert "1.0% of requests" in findings[0].reason


def test_rare_user_agent_emits_one_finding_per_agent_not_per_request():
    findings = detect_rare_user_agent(entries_at([0, 1, 2, 3], user_agent="curl/8.4.0"))

    assert len(findings) == 1


def test_rare_user_agent_ignores_entries_with_no_agent():
    assert detect_rare_user_agent([entry(user_agent=None)]) == []


# --- byte volume --------------------------------------------------------------


def test_byte_volume_flags_an_outsized_download():
    normal = [entry(bytes_recv=45_000 + i * 5_000) for i in range(12)]
    exfil = [entry(bytes_recv=90_000_000)]

    findings = detect_byte_volume(normal + exfil)

    assert len(findings) == 1
    assert findings[0].entry_id == exfil[0].id
    assert findings[0].severity == "critical"
    assert "downloaded" in findings[0].reason


def test_byte_volume_flags_an_outsized_upload():
    normal = [entry(bytes_sent=400 + i * 50) for i in range(12)]
    exfil = [entry(bytes_sent=5_000_000)]

    findings = detect_byte_volume(normal + exfil)

    assert len(findings) == 1
    assert "uploaded" in findings[0].reason


def test_byte_volume_ignores_ordinary_variation():
    assert detect_byte_volume([entry(bytes_recv=40_000 + i * 5_000) for i in range(15)]) == []


def test_byte_volume_needs_enough_samples_for_a_baseline():
    """Three requests do not establish what 'normal' looks like."""
    small = [entry(bytes_recv=1_000), entry(bytes_recv=1_100), entry(bytes_recv=90_000_000)]

    assert detect_byte_volume(small) == []


def test_byte_volume_excludes_zero_byte_rows_from_the_baseline():
    """Blocked requests transfer nothing; counting them would make any real
    transfer look like an outlier."""
    blocked = [entry(bytes_recv=0, bytes_sent=0, action="Blocked") for _ in range(20)]
    normal = [entry(bytes_recv=40_000 + i * 5_000, bytes_sent=500) for i in range(10)]

    assert detect_byte_volume(blocked + normal) == []


def test_byte_volume_is_blind_to_a_perfectly_uniform_baseline():
    """Known limitation, pinned so it stays a decision rather than a surprise.

    With no spread there is no interquartile range to measure against, so the
    detector abstains rather than guess a scale. Real proxy traffic always
    varies; a file this uniform is synthetic.
    """
    uniform = entries_at(list(range(12)), bytes_recv=50_000)

    assert detect_byte_volume(uniform + [entry(bytes_recv=90_000_000)]) == []


def test_byte_volume_only_flags_the_high_side():
    normal = [entry(bytes_recv=50_000_000 + i * 1_000) for i in range(12)]
    tiny = [entry(bytes_recv=1)]

    assert detect_byte_volume(normal + tiny) == []


# --- host sweep ---------------------------------------------------------------


def test_host_sweep_flags_scripted_multi_host_discovery():
    sweep = [
        entry(
            ts=NIGHT.replace(second=index),
            url=f"https://host-{index}.example.test/probe",
            user_agent="masscan/1.3",
        )
        for index in range(5)
    ]

    findings = detect_host_sweep(sweep)

    assert len(findings) == 1
    assert findings[0].type == "host_sweep"
    assert "5 distinct hosts" in findings[0].reason


def test_host_sweep_ignores_normal_browser_fanout():
    browser_fanout = [
        entry(ts=NIGHT.replace(second=index), url=f"https://cdn-{index}.example.test/asset.js")
        for index in range(8)
    ]

    assert detect_host_sweep(browser_fanout) == []


def test_host_sweep_ignores_scripted_requests_to_one_host():
    repeated = entries_at(
        [0, 1, 2, 3, 4, 5],
        url="https://one.example.test/probe",
        user_agent="curl/8.4.0",
    )

    assert detect_host_sweep(repeated) == []


# --- tool download ------------------------------------------------------------


def test_tool_download_flags_allowed_executable_payload():
    payload = entry(
        url="https://downloads.example.test/agent.exe",
        bytes_recv=4_000_000,
        user_agent="python-requests/2.32",
    )

    findings = detect_tool_download([payload])

    assert len(findings) == 1
    assert findings[0].type == "tool_download"
    assert findings[0].entry_id == payload.id


def test_tool_download_ignores_blocked_or_tiny_payloads():
    blocked = entry(
        url="https://downloads.example.test/agent.exe",
        bytes_recv=4_000_000,
        action="Blocked",
    )
    tiny = entry(url="https://downloads.example.test/agent.exe", bytes_recv=12_000)

    assert detect_tool_download([blocked, tiny]) == []


def test_tool_download_ignores_normal_browser_download():
    installer = entry(
        url="https://downloads.example.test/browser.exe",
        bytes_recv=40_000_000,
    )

    assert detect_tool_download([installer]) == []


# --- cloud upload -------------------------------------------------------------


def test_cloud_upload_flags_large_transfer_to_known_service():
    upload = entry(
        url="https://drive.google.com/upload/drive/v3/files",
        bytes_sent=250_000_000,
    )

    findings = detect_cloud_upload([upload])

    assert len(findings) == 1
    assert findings[0].type == "cloud_upload"
    assert findings[0].severity == "critical"


def test_cloud_upload_ignores_small_or_non_cloud_transfers():
    small = entry(url="https://drive.google.com/upload", bytes_sent=2_000_000)
    private = entry(url="https://storage.corp.test/upload", bytes_sent=250_000_000)

    assert detect_cloud_upload([small, private]) == []


# --- off hours ----------------------------------------------------------------


def test_off_hours_flags_middle_of_the_night_activity():
    findings = detect_off_hours(entries_at([0, 60, 120], base=NIGHT))

    assert len(findings) == 1
    assert findings[0].type == "off_hours"
    assert "middle of the night" in findings[0].reason


def test_off_hours_ignores_business_hours_activity():
    assert detect_off_hours(entries_at([0, 60, 120])) == []


def test_off_hours_flags_weekend_activity_during_the_day():
    findings = detect_off_hours(entries_at([0], base=SATURDAY_MIDDAY))

    assert len(findings) == 1
    assert "weekend" in findings[0].reason


def test_off_hours_scores_deep_night_above_the_evening():
    evening = datetime(2026, 7, 14, 21, 0, tzinfo=timezone.utc)
    night_finding = detect_off_hours(entries_at([0], base=NIGHT))[0]
    evening_finding = detect_off_hours(entries_at([0], base=evening))[0]

    assert night_finding.confidence > evening_finding.confidence


def test_off_hours_anchors_the_finding_to_the_earliest_request():
    night = entries_at([0, 60, 120], base=NIGHT)

    assert detect_off_hours(night)[0].entry_id == night[0].id


# --- engine -------------------------------------------------------------------


def test_engine_ranks_findings_by_weighted_score():
    burst_at_night = entries_at([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], base=NIGHT)
    findings = run_detectors(burst_at_night)
    types = [f.type for f in findings]

    assert "ip_burst" in types and "off_hours" in types
    # off_hours is the weakest signal and must not outrank a saturated burst.
    assert types.index("ip_burst") < types.index("off_hours")


def test_engine_returns_nothing_for_unremarkable_traffic():
    quiet = [
        entry(ts=None, src_ip=f"10.0.4.{i}", bytes_recv=40_000 + i * 1_000)
        for i in range(10)
    ]

    assert run_detectors(quiet) == []


def test_engine_handles_an_empty_file():
    assert run_detectors([]) == []


def test_engine_returns_every_finding_and_leaves_capping_to_the_caller():
    """`run_detectors` must not truncate: totals are computed from its output."""
    bursts = [
        e
        for n in range(MAX_FINDINGS + 10)
        for e in entries_at([0, 1, 2, 3, 4, 5], src_ip=f"10.9.{n // 256}.{n % 256}")
    ]
    findings = run_detectors(bursts)

    assert len(findings) == MAX_FINDINGS + 10
    assert len(top_findings(findings)) == MAX_FINDINGS


def test_engine_keeps_going_when_one_detector_raises(monkeypatch):
    def exploding_detector(entries):
        raise RuntimeError("detector bug")

    monkeypatch.setattr(engine, "DETECTORS", (exploding_detector, *engine.DETECTORS))
    findings = run_detectors(entries_at([0, 1, 2, 3, 4, 5]))

    assert any(f.type == "ip_burst" for f in findings)


# --- untrusted field handling -------------------------------------------------


def test_reason_strips_control_characters_from_attacker_supplied_agents():
    """A UA is chosen by the client; newlines in it must not forge log structure."""
    forged = "curl/8.4.0\n2026-07-14T09:00:00Z,admin,10.0.0.1,FAKE ROW"
    reason = detect_rare_user_agent([entry(user_agent=forged)])[0].reason

    assert "\n" not in reason


def test_reason_truncates_an_absurdly_long_user_agent():
    reason = detect_rare_user_agent([entry(user_agent="curl/" + "A" * 5_000)])[0].reason

    assert len(reason) < 300
