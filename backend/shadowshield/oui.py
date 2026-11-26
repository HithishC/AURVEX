"""
Local MAC vendor (OUI) lookup.

Dataset provenance and license (verify before relying on this in a
compliance-sensitive context -- this note documents what was done here,
not a legal opinion):

- The prefix -> vendor-name pairs below were hand-typed by the author
  from memory of commonly recognized, publicly documented OUI
  assignments (the kind printed in vendor documentation, NIC labels,
  and widely mirrored "OUI lookup" references). They were NOT
  downloaded or scraped from IEEE's own MA-L registry file in this
  session, and IEEE's current terms of use for redistributing their
  registry data verbatim have NOT been checked here.
- If this table is ever regenerated directly from IEEE's published
  MA-L/MA-M/MA-S CSV registry (https://standards-oui.ieee.org/), the
  applicable IEEE terms of use for that download must be reviewed at
  that time and referenced here explicitly. Do not assume unlimited
  redistribution rights without reading IEEE's current terms.
- No network calls are made at runtime either way: this is a static,
  in-process table. Coverage is intentionally small -- anything not
  listed returns "Unknown" rather than a guess, which is safe
  regardless of the above.
- Locally administered and multicast addresses are detected from the
  MAC's own bits and are never looked up in this table, since such
  addresses (e.g. randomized Wi-Fi MACs) do not reliably encode a real
  manufacturer OUI.
"""

from __future__ import annotations

from .normalize import normalize_mac

# OUI prefix (first 3 octets, lowercase, colon-separated) -> vendor name.
#
# Deliberately short. Each entry below is one I can state with real
# confidence as a widely and consistently documented assignment (the
# kind repeated verbatim across independent vendor docs, hypervisor
# defaults, and OUI-lookup references), not something recalled loosely
# from memory. During this cleanup pass, every prefix I was not
# genuinely confident about was removed rather than kept as a guess --
# this still has not been cross-checked against IEEE's own registry
# file (see module docstring), so treat even these as "commonly cited",
# not "IEEE-verified", until that check is actually done.
OUI_PREFIXES: dict[str, str] = {
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Foundation",
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5d": "Microsoft Hyper-V",
}


def mac_address_kind(mac: str) -> str:
    """
    Classify the MAC's own structural bits (not a vendor lookup).

    Returns one of: "Multicast", "Locally Administered", "Universal",
    or "Invalid" when the MAC cannot be parsed. Uses the same MAC
    normalization (hyphen/dot formats, case) as the rest of the
    pipeline (shadowshield.normalize.normalize_mac), so a MAC that
    reaches this function in any input format the rest of the system
    already accepts is classified consistently.
    """

    mac = normalize_mac(mac)
    parts = mac.split(":")

    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        return "Invalid"

    try:
        first_octet = int(parts[0], 16)
    except ValueError:
        return "Invalid"

    if first_octet & 0x01:
        return "Multicast"

    if first_octet & 0x02:
        return "Locally Administered"

    return "Universal"


def lookup_vendor(mac: str) -> str:
    """
    Return a known vendor name for a universally-administered MAC, or
    "Unknown" when the OUI is not in the local table, the address is
    locally administered/randomized, multicast, or invalid. Never
    invents a vendor name.
    """

    mac = normalize_mac(mac)
    kind = mac_address_kind(mac)

    if kind != "Universal":
        return "Unknown"

    prefix = ":".join(mac.split(":")[:3])
    return OUI_PREFIXES.get(prefix, "Unknown")
