from shadowshield.detection import compare_device
from shadowshield.oui import lookup_vendor, mac_address_kind
from shadowshield.risk import calculate_risk


# ---------------------------------------------------------------------
# Evidence tiers / Insufficient Evidence
# ---------------------------------------------------------------------

def test_strong_evidence_is_not_insufficient():
    device = {
        "mac": "3c:ca:9f:aa:bb:cc",
        "ip": "10.0.0.5",
        "hostname": "laptop1",
        "vendor": "",
        "ports": ["80"],
        "protocols": ["TCP"],
    }
    result = compare_device(device, {})
    assert result["identity_tier"] == "Strong"
    assert result["status"] != "Insufficient Evidence"


def test_partial_evidence_is_not_insufficient():
    # Two independent signals (ip + ports) -> Partial, not Insufficient.
    device = {
        "mac": "aa:bb:cc:dd:ee:10",
        "ip": "10.0.0.11",
        "hostname": "",
        "vendor": "",
        "ports": ["443"],
        "protocols": [],
    }
    result = compare_device(device, {})
    assert result["identity_tier"] == "Partial"
    assert result["status"] != "Insufficient Evidence"


def test_single_ip_alone_is_insufficient():
    # A single signal (IP only) must not be treated as sufficient identity.
    device = {
        "mac": "aa:bb:cc:dd:ee:11",
        "ip": "10.0.0.12",
        "hostname": "",
        "vendor": "",
        "ports": [],
        "protocols": [],
    }
    result = compare_device(device, {})
    assert result["identity_tier"] == "Insufficient"
    assert result["status"] == "Insufficient Evidence"
    assert result["authorization_status"] == "Review Required"


def test_missing_vendor_and_hostname_alone_is_not_insufficient():
    # Missing vendor/hostname must never by themselves cause
    # "Insufficient Evidence" when other signals are present.
    device = {
        "mac": "aa:bb:cc:dd:ee:12",
        "ip": "10.0.0.13",
        "hostname": "",
        "vendor": "",
        "ports": ["22"],
        "protocols": ["TCP"],
    }
    result = compare_device(device, {})
    assert result["identity_tier"] == "Strong"
    assert result["status"] != "Insufficient Evidence"


# ---------------------------------------------------------------------
# Review Required vs Changed vs Unauthorized
# ---------------------------------------------------------------------

APPROVED_BASELINE = {
    "aa:bb:cc:dd:ee:20": {
        "mac": "aa:bb:cc:dd:ee:20",
        "vendor": "cisco",
        "hostname": "host20",
        "ports": ["80"],
        "protocols": ["TCP"],
        "fingerprint": {},
    }
}


def test_strong_evidence_mismatch_is_changed():
    device = {
        "mac": "aa:bb:cc:dd:ee:20",
        "ip": "10.0.0.20",
        "hostname": "host20-renamed",
        "vendor": "dell",
        "ports": ["443"],
        "protocols": ["UDP"],
    }
    result = compare_device(device, APPROVED_BASELINE)
    assert result["status"] == "Changed"
    assert result["authorization_status"] == "Review Required"


def test_partial_evidence_mismatch_is_review_required_not_changed():
    device = {
        "mac": "aa:bb:cc:dd:ee:20",
        "ip": "10.0.0.20",
        "hostname": "",
        "vendor": "",
        "ports": ["443"],
        "protocols": [],
    }
    result = compare_device(device, APPROVED_BASELINE)
    assert result["status"] == "Review Required"
    assert result["authorization_status"] == "Review Required"


def test_unknown_device_is_not_review_required():
    # A brand-new device with no approved baseline is Unauthorized,
    # not Review Required -- the two must stay distinct.
    device = {
        "mac": "aa:bb:cc:dd:ee:21",
        "ip": "10.0.0.21",
        "hostname": "new-device",
        "vendor": "intel",
        "ports": ["80"],
        "protocols": ["TCP"],
    }
    result = compare_device(device, {})
    assert result["status"] == "Unknown"
    assert result["authorization_status"] == "Unauthorized"


def test_known_device_is_authorized_not_review_required():
    device = {
        "mac": "aa:bb:cc:dd:ee:20",
        "ip": "10.0.0.20",
        "hostname": "host20",
        "vendor": "cisco",
        "ports": ["80"],
        "protocols": ["TCP"],
    }
    result = compare_device(device, APPROVED_BASELINE)
    assert result["status"] == "Known"
    assert result["authorization_status"] == "Authorized"


# ---------------------------------------------------------------------
# Vendor / OUI
# ---------------------------------------------------------------------

def test_mac_address_kind_universal_unicast():
    assert mac_address_kind("b8:27:eb:11:22:33") == "Universal"


def test_mac_address_kind_locally_administered_unicast():
    assert mac_address_kind("02:00:00:11:22:33") == "Locally Administered"


def test_mac_address_kind_multicast():
    assert mac_address_kind("01:00:5e:00:00:01") == "Multicast"
    assert mac_address_kind("ff:ff:ff:ff:ff:ff") == "Multicast"


def test_mac_address_kind_invalid():
    assert mac_address_kind("") == "Invalid"
    assert mac_address_kind("not-a-mac") == "Invalid"
    assert mac_address_kind("aa:bb:cc:dd:ee") == "Invalid"


def test_mac_address_kind_normalizes_alternate_formats():
    # Hyphen-separated and dotted (Cisco-style) input must classify the
    # same as the canonical colon-separated lowercase form.
    assert mac_address_kind("B8-27-EB-11-22-33") == "Universal"
    assert mac_address_kind("b827.eb11.2233") == "Universal"


def test_oui_lookup_fills_known_vendor():
    assert lookup_vendor("b8:27:eb:11:22:33") == "Raspberry Pi Foundation"


def test_oui_lookup_normalizes_alternate_mac_formats():
    assert lookup_vendor("B8-27-EB-11-22-33") == "Raspberry Pi Foundation"


def test_oui_lookup_returns_unknown_for_unlisted_prefix():
    assert lookup_vendor("00:00:00:11:22:33") == "Unknown"


def test_oui_lookup_never_guesses_for_locally_administered_mac():
    # 02:... has the locally-administered bit set -> randomized/virtual,
    # must never be treated as a real OUI even if the prefix happens to
    # collide with a listed universal OUI.
    assert mac_address_kind("02:11:22:33:44:55") == "Locally Administered"
    assert lookup_vendor("02:11:22:33:44:55") == "Unknown"


def test_oui_lookup_returns_unknown_for_multicast_mac():
    assert mac_address_kind("01:00:5e:00:00:01") == "Multicast"
    assert lookup_vendor("01:00:5e:00:00:01") == "Unknown"


def test_compare_device_fills_blank_vendor_from_oui():
    device = {
        "mac": "b8:27:eb:aa:bb:cc",
        "ip": "10.0.0.30",
        "hostname": "",
        "vendor": "",
        "ports": ["22"],
        "protocols": ["TCP"],
    }
    result = compare_device(device, {})
    assert result["vendor"] == "Raspberry Pi Foundation"
    assert result["vendor_source"] == "oui_lookup"


def test_compare_device_preserves_explicit_vendor():
    device = {
        "mac": "b8:27:eb:aa:bb:dd",
        "ip": "10.0.0.31",
        "hostname": "",
        "vendor": "custom-vendor",
        "ports": ["22"],
        "protocols": ["TCP"],
    }
    result = compare_device(device, {})
    assert result["vendor"] == "custom-vendor"
    assert result["vendor_source"] == "observed"


def test_compare_device_leaves_vendor_blank_when_unresolvable():
    device = {
        "mac": "02:11:22:33:44:66",
        "ip": "10.0.0.32",
        "hostname": "",
        "vendor": "",
        "ports": ["22"],
        "protocols": ["TCP"],
    }
    result = compare_device(device, {})
    assert result["vendor"] == ""
    assert result["vendor_source"] == "unavailable"


# ---------------------------------------------------------------------
# Risk engine: independent rules combine correctly
# ---------------------------------------------------------------------

RICH_IDENTITY = {"mac": "aa:bb:cc:dd:ee:40", "ip": "10.0.0.40", "hostname": "h40"}


def test_risk_unknown_rule_alone_is_medium_band():
    # Score of exactly 30 is the Low/Medium boundary -> Medium per risk.py.
    # Identity fields are filled in so the separate "insufficient identity"
    # rule doesn't also fire and contaminate this single-rule check.
    risk = calculate_risk(
        "Unknown", {**RICH_IDENTITY, "ports": [], "protocols": []}, None
    )
    assert risk["score"] == 30
    assert risk["band"] == "Medium"
    assert any("not in approved inventory" in r for r in risk["reasons"])


def test_risk_unexpected_port_rule_adds_independently():
    risk = calculate_risk(
        "Known",
        {**RICH_IDENTITY, "ports": ["9999"], "protocols": []},
        {"allowed_ports": ["80"]},
    )
    assert risk["score"] == 20
    assert risk["unexpected_ports"] == [9999]


def test_risk_multiple_independent_indicators_combine():
    # Unknown (+30) stacked with an unexpected port (+20) -> 50, Medium.
    risk = calculate_risk(
        "Unknown",
        {**RICH_IDENTITY, "ports": ["9999"], "protocols": []},
        None,
    )
    assert risk["score"] == 50
    assert risk["band"] == "Medium"
    assert len(risk["reasons"]) == 2


def test_risk_no_high_risk_indicators_is_low_or_medium_never_fabricated():
    # A clean, known device with no unexpected ports triggers no rules.
    risk = calculate_risk(
        "Known",
        {**RICH_IDENTITY, "ports": ["80"], "protocols": ["TCP"]},
        {"allowed_ports": ["80"]},
    )
    assert risk["score"] == 0
    assert risk["band"] == "Low"
    assert risk["reasons"] == ["No configured risk rules were triggered"]


def test_risk_insufficient_identity_rule_fires_independently():
    # Thin identity (fewer than MIN_IDENTITY_FIELDS) adds its own points
    # even when status is "Known" and ports are within baseline.
    risk = calculate_risk(
        "Known",
        {"ports": ["80"], "protocols": ["TCP"]},
        {"allowed_ports": ["80"]},
    )
    assert risk["score"] == 10
    assert any("Insufficient identity fields" in r for r in risk["reasons"])
