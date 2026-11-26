from __future__ import annotations

from .fingerprint import comparable_mismatches
from .risk import calculate_risk
from .oui import lookup_vendor, mac_address_kind


# Identity-tier thresholds, counted over five independent signals:
# IP, hostname, vendor, protocol evidence, port evidence.
#
#   0-1 signals  -> "Insufficient" (a single signal, e.g. IP alone, is
#                   explicitly not enough per design requirement).
#   2 signals    -> "Partial" (some identity evidence, but not enough
#                   to confidently call a baseline mismatch "Changed").
#   3+ signals   -> "Strong" (enough independent corroborating evidence
#                   to trust a status decision). Missing vendor or
#                   hostname alone never drops a device below "Strong"
#                   as long as other signals are present.
IDENTITY_TIER_INSUFFICIENT_MAX = 1
IDENTITY_TIER_PARTIAL_MAX = 2


def _resolve_vendor(observed: dict) -> tuple[str, str]:
    """
    Fill in a vendor name from the local OUI table when the observed
    record has none. Never invents a name: falls back to "" with
    source "unavailable" when the OUI is unknown, locally administered,
    multicast, or invalid.
    """

    vendor = str(observed.get("vendor", "")).strip()

    if vendor:
        return vendor, "observed"

    mac = str(observed.get("mac", "")).strip()
    looked_up = lookup_vendor(mac)

    if looked_up != "Unknown":
        return looked_up, "oui_lookup"

    return "", "unavailable"


def _identity_signals(observed: dict, vendor: str) -> dict:
    ip = str(observed.get("ip", "")).strip().lower()

    invalid_ips = {
        "",
        "0.0.0.0",
        "unknown",
        "none",
        "n/a",
        "-",
    }

    return {
        "ip": ip not in invalid_ips,
        "hostname": bool(str(observed.get("hostname", "")).strip()),
        "vendor": bool(vendor.strip()),
        "protocols": bool(observed.get("protocols")),
        "ports": bool(observed.get("ports")),
    }


def _identity_tier(signals: dict) -> str:
    """
    Strong / Partial / Insufficient classification used to decide
    whether a status conclusion (Known/Unknown/Changed) can be trusted,
    or whether evidence is too thin (Insufficient Evidence) or
    ambiguous against a baseline (Review Required).
    """

    present = sum(signals.values())

    if present <= IDENTITY_TIER_INSUFFICIENT_MAX:
        return "Insufficient"

    if present <= IDENTITY_TIER_PARTIAL_MAX:
        return "Partial"

    return "Strong"


def _evidence_quality(observed: dict, signals: dict | None = None) -> tuple[str, list[str]]:
    """
    Transparent evidence-quality assessment, separate from the
    Known/Unknown/Changed/Insufficient Evidence status. This explains
    *why* a device's identity evidence is strong or weak, independent
    of whether it happens to match an approved-inventory baseline.
    """

    signals = signals if signals is not None else _identity_signals(
        observed, str(observed.get("vendor", ""))
    )

    reasons = []

    if not signals["ip"]:
        reasons.append("No usable IP address observed.")
    if not signals["hostname"]:
        reasons.append("No hostname observed.")
    if not signals["vendor"]:
        reasons.append("No vendor/OUI information available.")
    if not signals["protocols"]:
        reasons.append("No protocol evidence observed.")
    if not signals["ports"]:
        reasons.append("No port activity observed.")

    tier = _identity_tier(signals)
    quality = {"Insufficient": "Low", "Partial": "Medium", "Strong": "High"}[tier]

    if not reasons:
        reasons.append("All identity evidence fields are present.")

    return quality, reasons


def _authorization_status(status: str) -> tuple[str, str]:
    """
    Authorization is separate from security risk.
    """

    mapping = {
        "Known": (
            "Authorized",
            "Device matches approved inventory.",
        ),
        "Unknown": (
            "Unauthorized",
            "Device is not in approved inventory.",
        ),
        "Changed": (
            "Review Required",
            "Observed device details differ from approved inventory.",
        ),
        "Review Required": (
            "Review Required",
            "Observed evidence conflicts with the approved baseline, "
            "but identity evidence is too thin to confirm the change "
            "with confidence. Manual verification is required.",
        ),
        "Insufficient Evidence": (
            "Review Required",
            "Not enough identifying information to determine authorization.",
        ),
    }

    return mapping.get(
        status,
        (
            "Review Required",
            "Authorization could not be determined.",
        ),
    )


def compare_device(
    observed: dict,
    approved_by_mac: dict,
    policy: dict | None = None,
) -> dict:

    mac = str(
        observed.get("mac", "")
    ).strip().lower()

    approved = approved_by_mac.get(mac)

    vendor, vendor_source = _resolve_vendor(observed)
    observed = {**observed, "vendor": vendor}

    signals = _identity_signals(observed, vendor)
    identity_tier = _identity_tier(signals)

    mismatches = []

    if identity_tier == "Insufficient":
        status = "Insufficient Evidence"

    elif approved is None:
        status = "Unknown"

    else:
        mismatches = comparable_mismatches(
            observed,
            approved,
        )

        if not mismatches:
            status = "Known"
        elif identity_tier == "Strong":
            # Enough corroborating evidence to trust the mismatch.
            status = "Changed"
        else:
            # Partial evidence + a mismatch is ambiguous: it could be a
            # real change or thin data producing a false mismatch.
            # Flag for manual review instead of asserting either way.
            status = "Review Required"

    authorization, authorization_reason = (
        _authorization_status(status)
    )

    risk = calculate_risk(
        status,
        observed,
        approved,
        policy,
    )

    evidence_quality, evidence_reasons = _evidence_quality(observed, signals)

    return {
        **observed,

        "status": status,

        "authorization_status": authorization,
        "authorization_reason": authorization_reason,

        "evidence_quality": evidence_quality,
        "evidence_reasons": evidence_reasons,
        "identity_tier": identity_tier,

        "vendor_source": vendor_source,
        "mac_address_kind": mac_address_kind(mac),

        "risk_score": risk["score"],
        "risk_band": risk["band"],
        "risk_reasons": risk["reasons"],

        "mismatch_fields": mismatches,

        "observed_ports": risk["observed_ports"],
        "unexpected_ports": risk["unexpected_ports"],
        "port_analysis": risk["port_analysis"],
    }


def analyze_devices(
    observed_devices: list[dict],
    approved_by_mac: dict,
    policy: dict | None = None,
) -> list[dict]:

    return [
        compare_device(
            device,
            approved_by_mac,
            policy,
        )
        for device in observed_devices
    ]