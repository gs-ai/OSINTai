"""Evidence-graded network classification for validated exit addresses.

Read this before trusting any ``residential_indicated`` label.

There is no free, public, authenticated-free dataset that proves an address is a
consumer subscriber line. What is available is *circumstantial*: the announcing
ASN, the AS organisation name, and the PTR record. This module combines those
signals, records which ones fired, and emits a confidence score. A label is a
lead, not a finding.

Precedence: a hosting/cloud ASN match is dispositive against a residential read.
Absent an ASN source, PTR wording carries the classification at reduced
confidence, because PTR records are operator-set text and are trivially
misleading.
"""

import csv
import ipaddress
import os
import re
import socket
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .models import (
    Classification,
    DATACENTER,
    HOSTING,
    MOBILE_INDICATED,
    RESIDENTIAL_INDICATED,
    UNKNOWN_CLASS,
)

# Well-known cloud / hosting / VPS autonomous systems. Not exhaustive by design:
# it is a high-precision denylist, so a miss degrades to "unknown" rather than
# producing a false residential claim.
CLOUD_ASNS: Dict[int, str] = {
    16509: "Amazon AWS",
    14618: "Amazon AWS",
    15169: "Google",
    396982: "Google Cloud",
    8075: "Microsoft Azure",
    8068: "Microsoft",
    14061: "DigitalOcean",
    16276: "OVH",
    24940: "Hetzner",
    63949: "Akamai/Linode",
    20473: "Vultr/Choopa",
    51167: "Contabo",
    45102: "Alibaba Cloud",
    37963: "Alibaba Cloud",
    31898: "Oracle Cloud",
    13335: "Cloudflare",
    54113: "Fastly",
    19551: "Incapsula",
    9009: "M247",
    60068: "Datacamp/CDN77",
    49505: "Selectel",
    197540: "netcup",
    35916: "MULTACOM",
    26496: "GoDaddy",
    46606: "Unified Layer",
    32475: "SingleHop",
    53667: "FranTech/BuyVM",
    62240: "Clouvider",
    212238: "Datacamp",
    136907: "Huawei Cloud",
    45090: "Tencent Cloud",
}

# PTR substrings that indicate consumer access networks. Ordered by how
# specific the token is; generic tokens carry less weight in scoring.
_RESIDENTIAL_PTR_TOKENS = (
    "dsl", "adsl", "vdsl", "cable", "cbl", "broadband", "bband", "fibertel",
    "dynamic", "dyn-", "dhcp", "pool", "client", "customer", "subscriber",
    "res.rr.com", "hsd1", "comcast", "charter", "spectrum", "cox.net",
    "verizon.net", "att.net", "sbcglobal", "bellsouth", "rogers", "telus",
    "virginm", "btcentralplus", "sky.com", "ono.com", "telecom",
)

_MOBILE_PTR_TOKENS = (
    "mobile", "lte", "3g", "4g", "5g", "gprs", "umts", "cellular",
    "wireless", "mnet", "mobil",
)

_DATACENTER_PTR_TOKENS = (
    "compute.amazonaws.com", "googleusercontent", "azure", "cloudapp",
    "digitalocean", "ovh.net", "hetzner", "linode", "vultr", "contabo",
    "server", "srv", "vps", "dedi", "dedicated", "colo", "hosted", "hosting",
    "datacenter", "data-center", "cloud", "node", "instance", "leaseweb",
    "choopa", "m247", "packet", "scaleway", "netcup", "gigenet", "quadranet",
)

_TOKEN_RE_CACHE: Dict[Tuple[str, ...], re.Pattern] = {}


def _token_pattern(tokens: Tuple[str, ...]) -> re.Pattern:
    if tokens not in _TOKEN_RE_CACHE:
        joined = "|".join(re.escape(token) for token in tokens)
        _TOKEN_RE_CACHE[tokens] = re.compile(joined, re.IGNORECASE)
    return _TOKEN_RE_CACHE[tokens]


def _matched_tokens(text: str, tokens: Tuple[str, ...]) -> List[str]:
    if not text:
        return []
    return sorted({m.group(0).lower() for m in _token_pattern(tokens).finditer(text)})


_ORG_HOSTING_RE = re.compile(
    r"\b(hosting|host|cloud|data\s*cent|datacent|vps|server|colo|dedicated|"
    r"网络|idc|telecom\s*idc)\b",
    re.IGNORECASE,
)
_ORG_ISP_RE = re.compile(
    r"\b(broadband|cable|dsl|fiber|fibre|communications?|telecom|telecomm|"
    r"internet\s*service|isp|residential)\b",
    re.IGNORECASE,
)


@dataclass
class AsnRecord:
    asn: int
    org: str = ""
    country: str = ""


class AsnTable:
    """Longest-prefix ASN lookup over an operator-supplied CIDR table.

    Expected format is a headerless or headed CSV/TSV with columns:
    ``cidr,asn,org,country``. This keeps the tool offline-capable and avoids
    shipping a stale copy of anyone's routing data. Build one from a public
    routing dump, an RIR extract, or a MaxMind ASN CSV export.
    """

    def __init__(self):
        self._v4: List[Tuple[ipaddress.IPv4Network, AsnRecord]] = []
        self._v6: List[Tuple[ipaddress.IPv6Network, AsnRecord]] = []

    def __len__(self) -> int:
        return len(self._v4) + len(self._v6)

    @classmethod
    def load(cls, path: str) -> "AsnTable":
        table = cls()
        resolved = os.path.abspath(os.path.expanduser(path))
        if not os.path.isfile(resolved):
            raise FileNotFoundError(f"ASN table not found: {resolved}")

        delimiter = "\t" if resolved.lower().endswith((".tsv", ".tab")) else ","
        with open(resolved, "r", encoding="utf-8", errors="ignore", newline="") as handle:
            for row in csv.reader(handle, delimiter=delimiter):
                if len(row) < 2:
                    continue
                cidr = row[0].strip()
                if not cidr or cidr.lower() in {"cidr", "network", "prefix"}:
                    continue
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    asn = int(str(row[1]).strip().upper().removeprefix("AS"))
                except ValueError:
                    continue
                record = AsnRecord(
                    asn=asn,
                    org=row[2].strip() if len(row) > 2 else "",
                    country=row[3].strip() if len(row) > 3 else "",
                )
                if isinstance(network, ipaddress.IPv4Network):
                    table._v4.append((network, record))
                else:
                    table._v6.append((network, record))

        # Longest prefix first so the first containing match is the most specific.
        table._v4.sort(key=lambda item: item[0].prefixlen, reverse=True)
        table._v6.sort(key=lambda item: item[0].prefixlen, reverse=True)
        return table

    def lookup(self, ip: str) -> Optional[AsnRecord]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        rows = self._v4 if addr.version == 4 else self._v6
        for network, record in rows:
            if addr in network:
                return record
        return None


def reverse_dns(ip: str, timeout_s: float = 2.0) -> Optional[str]:
    """Best-effort PTR lookup. Returns None on any resolver failure."""
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_s)
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror, UnicodeError):
        return None
    finally:
        socket.setdefaulttimeout(previous)


def classify(
    ip: str,
    asn_table: Optional[AsnTable] = None,
    ptr: Optional[str] = None,
    resolve_ptr: bool = True,
    ptr_timeout_s: float = 2.0,
) -> Classification:
    """Classify an exit address from ASN and PTR evidence.

    Every signal that fires is recorded in ``basis`` so a reviewer can see
    exactly why a label was assigned. Confidence never reaches 1.0: none of
    these signals is a subscriber-line record.
    """
    result = Classification()
    if ptr is None and resolve_ptr:
        ptr = reverse_dns(ip, ptr_timeout_s)
    result.ptr = ptr

    asn_record = asn_table.lookup(ip) if asn_table else None
    if asn_record:
        result.asn = asn_record.asn
        result.as_org = asn_record.org or None
        result.country = asn_record.country or None

    residential_hits = _matched_tokens(ptr or "", _RESIDENTIAL_PTR_TOKENS)
    mobile_hits = _matched_tokens(ptr or "", _MOBILE_PTR_TOKENS)
    datacenter_hits = _matched_tokens(ptr or "", _DATACENTER_PTR_TOKENS)

    # 1. Known cloud/hosting ASN is dispositive.
    if result.asn in CLOUD_ASNS:
        result.network_class = DATACENTER
        result.as_org = result.as_org or CLOUD_ASNS[result.asn]
        result.basis.append(f"ASN AS{result.asn} on known cloud/hosting list ({CLOUD_ASNS[result.asn]})")
        result.confidence = 0.9
        if residential_hits:
            result.basis.append(
                "PTR carries consumer-style tokens but ASN evidence overrides: "
                + ", ".join(residential_hits)
            )
        return result

    # 2. AS organisation name indicating hosting.
    if result.as_org and _ORG_HOSTING_RE.search(result.as_org):
        result.network_class = HOSTING
        result.basis.append(f"AS org name indicates hosting: {result.as_org!r}")
        result.confidence = 0.7
        return result

    # 3. PTR indicating datacenter.
    if datacenter_hits:
        result.network_class = DATACENTER
        result.basis.append("PTR datacenter tokens: " + ", ".join(datacenter_hits))
        result.confidence = 0.6 if len(datacenter_hits) > 1 else 0.45
        return result

    # 4. Mobile carrier indicators.
    if mobile_hits:
        result.network_class = MOBILE_INDICATED
        result.basis.append("PTR mobile-carrier tokens: " + ", ".join(mobile_hits))
        result.confidence = 0.4
        if result.as_org and _ORG_ISP_RE.search(result.as_org):
            result.basis.append(f"AS org name consistent with an access network: {result.as_org!r}")
            result.confidence = 0.55
        return result

    # 5. Consumer access indicators. Capped low on purpose.
    if residential_hits:
        result.network_class = RESIDENTIAL_INDICATED
        result.basis.append("PTR consumer-access tokens: " + ", ".join(residential_hits))
        result.confidence = 0.35 if len(residential_hits) == 1 else 0.5
        if result.as_org and _ORG_ISP_RE.search(result.as_org):
            result.basis.append(f"AS org name consistent with an access ISP: {result.as_org!r}")
            result.confidence = min(0.65, result.confidence + 0.15)
        result.basis.append(
            "PTR text is operator-controlled; treat as a lead requiring confirmation"
        )
        return result

    # 6. Nothing usable fired.
    result.network_class = UNKNOWN_CLASS
    if not asn_table:
        result.basis.append("no ASN table loaded (--asn-table); ASN evidence unavailable")
    if not ptr:
        result.basis.append("no PTR record resolved")
    if not result.basis:
        result.basis.append("no ASN or PTR signal matched a known pattern")
    result.confidence = 0.0
    return result


def classification_summary(rows: List[Dict]) -> Dict[str, int]:
    """Counts by network_class, for the CLI status line and cycle metrics."""
    summary: Dict[str, int] = {}
    for row in rows:
        key = row.get("network_class", UNKNOWN_CLASS)
        summary[key] = summary.get(key, 0) + 1
    return summary
