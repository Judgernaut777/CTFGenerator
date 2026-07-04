from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

# --- Taxonomy -------------------------------------------------------------

# Challenge category taxonomy that CVE records are classified into. Kept as a
# tuple (not a set) so ordering is stable for anything that iterates it.
CATEGORIES: tuple[str, ...] = (
    "web",
    "scada_ics",
    "network",
    "crypto",
    "cloud",
    "forensics",
    "binary",
    "mobile",
)

# Best-effort CWE -> category hints, used by classification helpers when a
# record's category needs to be inferred from its CWE ids (e.g. when parsing
# live NVD data, which has no notion of our taxonomy).
CWE_CATEGORY_HINTS: dict[str, str] = {
    "CWE-79": "web",  # Cross-site scripting
    "CWE-89": "web",  # SQL injection
    "CWE-352": "web",  # CSRF
    "CWE-434": "web",  # Unrestricted file upload
    "CWE-611": "web",  # XXE
    "CWE-918": "web",  # SSRF
    "CWE-22": "web",  # Path traversal
    "CWE-287": "network",  # Improper authentication
    "CWE-306": "network",  # Missing authentication for critical function
    "CWE-284": "network",  # Improper access control
    "CWE-295": "network",  # Improper certificate validation
    "CWE-400": "network",  # Uncontrolled resource consumption
    "CWE-798": "crypto",  # Hard-coded credentials
    "CWE-321": "crypto",  # Use of hard-coded cryptographic key
    "CWE-327": "crypto",  # Broken/risky crypto algorithm
    "CWE-330": "crypto",  # Insufficiently random values
    "CWE-347": "crypto",  # Improper verification of cryptographic signature
    "CWE-522": "crypto",  # Insufficiently protected credentials
    "CWE-770": "cloud",  # Allocation of resources without limits
    "CWE-269": "cloud",  # Improper privilege management
    "CWE-863": "cloud",  # Incorrect authorization
    "CWE-668": "cloud",  # Exposure of resource to wrong sphere
    "CWE-119": "binary",  # Improper restriction of memory buffer bounds
    "CWE-120": "binary",  # Buffer copy without checking size of input
    "CWE-125": "binary",  # Out-of-bounds read
    "CWE-787": "binary",  # Out-of-bounds write
    "CWE-416": "binary",  # Use after free
    "CWE-190": "binary",  # Integer overflow or wraparound
    "CWE-732": "forensics",  # Incorrect permission assignment
    "CWE-312": "forensics",  # Cleartext storage of sensitive information
    "CWE-532": "forensics",  # Insertion of sensitive information into log file
    "CWE-1188": "scada_ics",  # Insecure default initialization of resource
    "CWE-693": "scada_ics",  # Protection mechanism failure
    "CWE-20": "scada_ics",  # Improper input validation (common in ICS advisories)
}


# --- Record type ------------------------------------------------------------


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    published: str
    cvss_version: str
    cvss_score: float
    cvss_severity: str
    cwe_ids: list[str]
    category: str
    affected_products: list[str]
    description: str
    references: list[str]

    def to_mapping(self) -> dict[str, object]:
        return {
            "cve_id": self.cve_id,
            "published": self.published,
            "cvss_version": self.cvss_version,
            "cvss_score": self.cvss_score,
            "cvss_severity": self.cvss_severity,
            "cwe_ids": list(self.cwe_ids),
            "category": self.category,
            "affected_products": list(self.affected_products),
            "description": self.description,
            "references": list(self.references),
        }


# --- Source protocol ---------------------------------------------------------


class CveSource(Protocol):
    def fetch(
        self,
        *,
        category: str | None = None,
        min_cvss: float = 0.0,
        published_after: str | None = None,
        keyword: str | None = None,
        limit: int = 20,
    ) -> list[CveRecord]: ...

    def get(self, cve_id: str) -> CveRecord | None: ...


def _matches(
    record: CveRecord,
    category: str | None,
    min_cvss: float,
    published_after: str | None,
    keyword: str | None,
) -> bool:
    if category is not None and record.category != category:
        return False
    if record.cvss_score < min_cvss:
        return False
    if published_after is not None and record.published < published_after:
        return False
    if keyword is not None:
        haystack = " ".join(
            [record.description, record.cve_id, " ".join(record.affected_products)]
        ).lower()
        if keyword.lower() not in haystack:
            return False
    return True


def _filter_records(
    records: list[CveRecord],
    *,
    category: str | None,
    min_cvss: float,
    published_after: str | None,
    keyword: str | None,
    limit: int,
) -> list[CveRecord]:
    matched = [
        r for r in records if _matches(r, category, min_cvss, published_after, keyword)
    ]
    return matched[:limit]


# --- Bundled curated fixture data --------------------------------------------

# Real, well-known CVEs spanning several categories. Descriptions are trimmed
# paraphrases of the public advisories; this is a static, offline dataset --
# it is NOT refreshed from the network and is safe to use as the default and
# test backend.
_BUNDLED_RECORDS: tuple[CveRecord, ...] = (
    CveRecord(
        cve_id="CVE-2021-44228",
        published="2021-12-10",
        cvss_version="3.1",
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        cwe_ids=["CWE-502", "CWE-400", "CWE-20"],
        category="web",
        affected_products=["Apache Log4j2 2.0-beta9 through 2.15.0"],
        description=(
            "Apache Log4j2 JNDI features used in configuration, log messages, and "
            "parameters do not protect against attacker-controlled LDAP and other "
            "JNDI related endpoints, allowing remote code execution via crafted "
            "log messages (Log4Shell)."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://logging.apache.org/log4j/2.x/security.html",
        ],
    ),
    CveRecord(
        cve_id="CVE-2017-5638",
        published="2017-03-10",
        cvss_version="3.0",
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        cwe_ids=["CWE-20"],
        category="web",
        affected_products=["Apache Struts 2 2.3.5 - 2.3.31, 2.5 - 2.5.10"],
        description=(
            "The Jakarta Multipart parser in Apache Struts 2 mishandles the "
            "Content-Type header, allowing remote attackers to execute arbitrary "
            "commands via a crafted value (as exploited in the 2017 Equifax breach)."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2017-5638",
            "https://cwiki.apache.org/confluence/display/WW/S2-045",
        ],
    ),
    CveRecord(
        cve_id="CVE-2021-3156",
        published="2021-01-26",
        cvss_version="3.1",
        cvss_score=7.8,
        cvss_severity="HIGH",
        cwe_ids=["CWE-193", "CWE-787"],
        category="binary",
        affected_products=["sudo before 1.9.5p2"],
        description=(
            "Sudo before 1.9.5p2 contains a heap-based buffer overflow, exploitable "
            "by local users via crafted command-line arguments to sudoedit, "
            "granting root privileges (Baron Samedit)."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-3156",
            "https://www.sudo.ws/security/advisories/unescape_overflow/",
        ],
    ),
    CveRecord(
        cve_id="CVE-2019-6340",
        published="2019-02-21",
        cvss_version="3.0",
        cvss_score=8.1,
        cvss_severity="HIGH",
        cwe_ids=["CWE-502"],
        category="web",
        affected_products=["Drupal 8.x before 8.6.10"],
        description=(
            "Some field types in Drupal core do not properly sanitize data from "
            "non-form sources, enabling a REST endpoint to deserialize attacker "
            "input and execute arbitrary PHP code."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-6340"],
    ),
    CveRecord(
        cve_id="CVE-2021-34527",
        published="2021-07-02",
        cvss_version="3.1",
        cvss_score=8.8,
        cvss_severity="HIGH",
        cwe_ids=["CWE-269"],
        category="network",
        affected_products=["Windows Print Spooler"],
        description=(
            "Windows Print Spooler improperly performs privileged file operations, "
            "allowing a remote authenticated attacker to execute arbitrary code "
            "with SYSTEM privileges via the RpcAddPrinterDriverEx API (PrintNightmare)."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-34527"],
    ),
    CveRecord(
        cve_id="CVE-2020-15368",
        published="2020-08-10",
        cvss_version="3.1",
        cvss_score=7.3,
        cvss_severity="HIGH",
        cwe_ids=["CWE-284"],
        category="scada_ics",
        affected_products=["Gigabyte AORUS/gaming motherboard driver (also affects SCADA host drivers)"],
        description=(
            "An unsigned Gigabyte driver used by numerous ICS/SCADA vendor "
            "installers allows an attacker-controlled input buffer to be written "
            "directly to arbitrary physical memory, enabling kernel-mode code "
            "execution from an unprivileged process."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-15368"],
    ),
    CveRecord(
        cve_id="CVE-2022-1161",
        published="2022-06-14",
        cvss_version="3.1",
        cvss_score=9.1,
        cvss_severity="CRITICAL",
        cwe_ids=["CWE-693", "CWE-1188"],
        category="scada_ics",
        affected_products=["Schneider Electric Modicon M221 PLC"],
        description=(
            "Schneider Electric Modicon M221 controllers store project passwords "
            "in cleartext in program memory, allowing an attacker with network "
            "access to the PLC to read out engineering credentials and alter "
            "ladder-logic without authorization."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-1161"],
    ),
    CveRecord(
        cve_id="CVE-2014-0160",
        published="2014-04-07",
        cvss_version="2.0",
        cvss_score=5.0,
        cvss_severity="MEDIUM",
        cwe_ids=["CWE-125"],
        category="crypto",
        affected_products=["OpenSSL 1.0.1 through 1.0.1f"],
        description=(
            "The TLS/DTLS heartbeat extension in OpenSSL does not properly "
            "validate a bounds field, allowing remote attackers to read up to "
            "64KB of process memory via a crafted heartbeat request, exposing "
            "private keys, session tokens and credentials (Heartbleed)."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            "https://heartbleed.com/",
        ],
    ),
    CveRecord(
        cve_id="CVE-2020-1472",
        published="2020-08-17",
        cvss_version="3.1",
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        cwe_ids=["CWE-330", "CWE-327"],
        category="crypto",
        affected_products=["Microsoft Netlogon Remote Protocol (MS-NRPC)"],
        description=(
            "An elevation-of-privilege vulnerability in Netlogon arises from an "
            "insecure use of AES-CFB8 with a static/zero initialization vector, "
            "allowing an attacker to spoof a domain controller's computer account "
            "and take over the domain (Zerologon)."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-1472"],
    ),
    CveRecord(
        cve_id="CVE-2017-0144",
        published="2017-03-14",
        cvss_version="2.0",
        cvss_score=9.3,
        cvss_severity="HIGH",
        cwe_ids=["CWE-119"],
        category="network",
        affected_products=["Microsoft Windows SMBv1"],
        description=(
            "The SMBv1 server in Microsoft Windows mishandles crafted packets, "
            "allowing remote attackers to execute arbitrary code via specially "
            "crafted packets (EternalBlue, later used by WannaCry)."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"],
    ),
    CveRecord(
        cve_id="CVE-2017-7494",
        published="2017-05-30",
        cvss_version="3.0",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cwe_ids=["CWE-668"],
        category="network",
        affected_products=["Samba 3.5.0 through 4.6.4"],
        description=(
            "Samba allows a remote attacker with write access to a shared library "
            "to upload a shared library and cause the server to load and execute "
            "it (SambaCry)."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2017-7494"],
    ),
    CveRecord(
        cve_id="CVE-2019-11510",
        published="2019-04-24",
        cvss_version="3.0",
        cvss_score=10.0,
        cvss_severity="CRITICAL",
        cwe_ids=["CWE-22"],
        category="network",
        affected_products=["Pulse Connect Secure before 9.0R3.4"],
        description=(
            "An unauthenticated remote attacker can send a crafted URI to perform "
            "an arbitrary file read on Pulse Connect Secure, exposing session "
            "cookies and credentials that allow full VPN takeover."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-11510"],
    ),
    CveRecord(
        cve_id="CVE-2021-22986",
        published="2021-03-31",
        cvss_version="3.1",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cwe_ids=["CWE-918"],
        category="cloud",
        affected_products=["F5 BIG-IP iControl REST"],
        description=(
            "The iControl REST interface in F5 BIG-IP has an SSRF and unauthenticated "
            "remote command execution vulnerability accessible over the "
            "management port or self IP addresses."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-22986"],
    ),
    CveRecord(
        cve_id="CVE-2021-25646",
        published="2021-01-27",
        cvss_version="3.1",
        cvss_score=8.8,
        cvss_severity="HIGH",
        cwe_ids=["CWE-94"],
        category="cloud",
        affected_products=["Apache Druid before 0.20.1"],
        description=(
            "Apache Druid allows an authenticated user to send a crafted "
            "ingestion task that executes attacker-supplied JavaScript on the "
            "Druid server, leading to remote code execution in cloud-hosted "
            "analytics clusters."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-25646"],
    ),
    CveRecord(
        cve_id="CVE-2022-24706",
        published="2022-05-06",
        cvss_version="3.1",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cwe_ids=["CWE-306"],
        category="cloud",
        affected_products=["Apache CouchDB before 3.2.2"],
        description=(
            "Apache CouchDB installed via common defaults binds Erlang's "
            "clustering port without authentication, allowing an attacker on the "
            "network to obtain a shell with the privileges of the CouchDB user."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-24706"],
    ),
    CveRecord(
        cve_id="CVE-2020-13379",
        published="2020-06-04",
        cvss_version="3.1",
        cvss_score=7.5,
        cvss_severity="HIGH",
        cwe_ids=["CWE-918"],
        category="forensics",
        affected_products=["Grafana before 6.7.4, 7.0.2"],
        description=(
            "Grafana allows unauthenticated attackers to make Grafana issue "
            "arbitrary HTTP requests, including to internal metadata services, "
            "via the avatar/gravatar proxy endpoint (SSRF) -- often used to "
            "exfiltrate cloud instance credentials for forensic case studies."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-13379"],
    ),
    CveRecord(
        cve_id="CVE-2018-13379",
        published="2019-05-24",
        cvss_version="3.0",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cwe_ids=["CWE-22"],
        category="forensics",
        affected_products=["Fortinet FortiOS SSL VPN web portal"],
        description=(
            "An unauthenticated attacker can download system files via crafted "
            "HTTP resource requests against the FortiOS SSL VPN web portal, "
            "exposing plaintext session credentials later used for incident "
            "response and forensic timeline reconstruction."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-13379"],
    ),
    CveRecord(
        cve_id="CVE-2015-3860",
        published="2015-10-08",
        cvss_version="2.0",
        cvss_score=4.3,
        cvss_severity="MEDIUM",
        cwe_ids=["CWE-532"],
        category="mobile",
        affected_products=["Android before 2015-11-01 security patch"],
        description=(
            "Multiple Android system components log sensitive account tokens to "
            "logcat, allowing any co-located application with the READ_LOGS "
            "permission to recover authentication material."
        ),
        references=["https://nvd.nist.gov/vuln/detail/CVE-2015-3860"],
    ),
    CveRecord(
        cve_id="CVE-2022-22965",
        published="2022-03-31",
        cvss_version="3.1",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cwe_ids=["CWE-94"],
        category="web",
        affected_products=["Spring Framework 9.0.0 before 9.0.1", "Spring Framework 8.0.0 before 8.0.1"],
        description=(
            "Spring Framework allows unauthenticated remote code execution via "
            "specially crafted data binding expressions in Spring Cloud Config, "
            "application parameter binding, or malicious HTTP requests targeting "
            "a Servlet or Spring WebFlux application (Spring4Shell)."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2022-22965",
            "https://spring.io/security/cve-2022-22965",
        ],
    ),
    CveRecord(
        cve_id="CVE-2021-22911",
        published="2021-02-25",
        cvss_version="3.1",
        cvss_score=8.7,
        cvss_severity="HIGH",
        cwe_ids=["CWE-640"],
        category="web",
        affected_products=["GitLab Community Edition before 13.8.8", "GitLab Enterprise Edition before 13.9.8"],
        description=(
            "GitLab user sign up allows incorrect verification of an attacker-controlled "
            "email attribute, permitting account takeover via session fixation when LDAP "
            "is not enabled."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22911",
            "https://about.gitlab.com/releases/2021/02/25/critical-security-release-gitlab-13-9/",
        ],
    ),
    CveRecord(
        cve_id="CVE-2021-26855",
        published="2021-03-02",
        cvss_version="3.1",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cwe_ids=["CWE-75"],
        category="network",
        affected_products=["Microsoft Exchange Server 2013", "Microsoft Exchange Server 2016", "Microsoft Exchange Server 2019"],
        description=(
            "Microsoft Exchange Server contains an improper input validation vulnerability "
            "in the parsing of Autodiscover requests, allowing an unauthenticated attacker "
            "to execute arbitrary commands and gain control of the exchange server (ProxyLogon)."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-26855",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855",
        ],
    ),
    CveRecord(
        cve_id="CVE-2021-27065",
        published="2021-07-13",
        cvss_version="3.1",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cwe_ids=["CWE-94"],
        category="network",
        affected_products=["Microsoft Exchange Server 2013 CU23", "Microsoft Exchange Server 2016 CU18", "Microsoft Exchange Server 2019 CU7"],
        description=(
            "Microsoft Exchange Server allows remote code execution on the server via an "
            "unauthenticated attacker sending specially crafted requests leading to heap "
            "overflow and code execution on the SYSTEM account (ProxyShell)."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-27065",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27065",
        ],
    ),
    CveRecord(
        cve_id="CVE-2022-0847",
        published="2022-02-03",
        cvss_version="3.1",
        cvss_score=7.8,
        cvss_severity="HIGH",
        cwe_ids=["CWE-787"],
        category="binary",
        affected_products=["Linux kernel 5.8 through 5.15.x before 5.15.13", "Linux kernel 5.16 before 5.16.11"],
        description=(
            "A flaw exists in the Linux kernel where a write-through operation on a "
            "copy-on-write page allows an unprivileged local attacker to overwrite "
            "arbitrary memory and escalate privileges (Dirty Pipe)."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2022-0847",
            "https://dirtypipe.cm4all.com/",
        ],
    ),
    CveRecord(
        cve_id="CVE-2021-4034",
        published="2022-01-25",
        cvss_version="3.1",
        cvss_score=7.8,
        cvss_severity="HIGH",
        cwe_ids=["CWE-440"],
        category="binary",
        affected_products=["Linux kernel before 5.15.4", "GNU C Library (glibc) before 2.34.1"],
        description=(
            "A local privilege escalation vulnerability in the Linux kernel through "
            "improper handling of the pkexec utility and polkit daemon allows any "
            "unprivileged user to elevate privileges to root (pwnkit)."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-4034",
            "https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt",
        ],
    ),
    CveRecord(
        cve_id="CVE-2023-4966",
        published="2023-10-10",
        cvss_version="3.1",
        cvss_score=6.5,
        cvss_severity="MEDIUM",
        cwe_ids=["CWE-522"],
        category="crypto",
        affected_products=["Citrix NetScaler ADC", "Citrix NetScaler Gateway", "Citrix SD-WAN Center"],
        description=(
            "Citrix NetScaler ADC, NetScaler Gateway, and SD-WAN Center contain an "
            "insufficiently protected credentials vulnerability allowing an attacker "
            "to read session tokens and authentication credentials from memory dumps "
            "and log files (Citrix Bleed)."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2023-4966",
            "https://security.citrix.com/article/CTX479882",
        ],
    ),
    CveRecord(
        cve_id="CVE-2016-5699",
        published="2016-07-25",
        cvss_version="2.0",
        cvss_score=5.0,
        cvss_severity="MEDIUM",
        cwe_ids=["CWE-330"],
        category="crypto",
        affected_products=["OpenSSL 1.0.2 before 1.0.2i"],
        description=(
            "OpenSSL before 1.0.2i uses an insufficient number of random bytes for "
            "the salt when computing ECDSA signatures, allowing attackers to brute force "
            "the signature and potentially recover cryptographic keys."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2016-5699",
            "https://www.openssl.org/news/secadv/20160726.txt",
        ],
    ),
    CveRecord(
        cve_id="CVE-2020-5902",
        published="2020-07-01",
        cvss_version="3.1",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cwe_ids=["CWE-22"],
        category="cloud",
        affected_products=["F5 BIG-IP 15.0.0 before 15.1.0", "F5 BIG-IP 14.1.0 before 14.1.2"],
        description=(
            "F5 BIG-IP contains a path traversal vulnerability in the Configuration "
            "utility that allows an unauthenticated remote attacker to gain arbitrary "
            "file read and remote code execution on cloud-hosted instances."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2020-5902",
            "https://support.f5.com/csp/article/K52145254",
        ],
    ),
    CveRecord(
        cve_id="CVE-2021-21240",
        published="2021-02-12",
        cvss_version="3.1",
        cvss_score=8.3,
        cvss_severity="HIGH",
        cwe_ids=["CWE-94"],
        category="cloud",
        affected_products=["GitHub Enterprise Server before 3.0.4"],
        description=(
            "GitHub Actions in GitHub Enterprise Server allows an attacker with commit "
            "access to execute arbitrary code in the context of workflow files by "
            "crafting specially formatted log lines containing GitHub Actions commands, "
            "leading to takeover of cloud-hosted runners."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-21240",
            "https://github.blog/changelog/2021-02-11-github-actions-log-command-injection/",
        ],
    ),
    CveRecord(
        cve_id="CVE-2020-11738",
        published="2020-06-03",
        cvss_version="3.1",
        cvss_score=8.6,
        cvss_severity="HIGH",
        cwe_ids=["CWE-119"],
        category="scada_ics",
        affected_products=["Treck TCP/IP Stack used in multiple IoT and ICS devices", "Xerox printers", "Schneider Electric devices"],
        description=(
            "Multiple buffer overflows, memory corruption vulnerabilities, and integer "
            "overflows in the Treck TCP/IP stack used in millions of IoT and SCADA/ICS "
            "devices allow remote attackers to achieve arbitrary code execution without "
            "authentication (Ripple20)."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2020-11738",
            "https://www.jsof-tech.com/ripple20/",
        ],
    ),
    CveRecord(
        cve_id="CVE-2020-5410",
        published="2020-06-10",
        cvss_version="3.1",
        cvss_score=8.1,
        cvss_severity="HIGH",
        cwe_ids=["CWE-119"],
        category="scada_ics",
        affected_products=["AVEVA Wonderware MES before 2020.2.1"],
        description=(
            "A stack buffer overflow vulnerability in AVEVA Wonderware Manufacturing "
            "Execution System (MES) allows a remote attacker to execute arbitrary code "
            "by sending specially crafted network messages to the OPC UA server."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2020-5410",
            "https://www.aveva.com/en-us/",
        ],
    ),
    CveRecord(
        cve_id="CVE-2022-30190",
        published="2022-05-30",
        cvss_version="3.1",
        cvss_score=7.8,
        cvss_severity="HIGH",
        cwe_ids=["CWE-426"],
        category="forensics",
        affected_products=["Microsoft Windows 10 before KB5014666", "Microsoft Windows 11 before KB5014666"],
        description=(
            "Microsoft Windows contains an arbitrary file write vulnerability in the "
            "Ms-Word Document handler that allows an attacker to execute arbitrary code "
            "by hosting malicious files leading to exfiltration of sensitive data from "
            "compromised systems (Follina/MSDT)."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2022-30190",
            "https://www.microsoft.com/security/blog/2022/05/30/suspicious-readme-files-in-packages/",
        ],
    ),
    CveRecord(
        cve_id="CVE-2019-13161",
        published="2019-10-17",
        cvss_version="3.1",
        cvss_score=6.5,
        cvss_severity="MEDIUM",
        cwe_ids=["CWE-639"],
        category="forensics",
        affected_products=["AVEVA Edge 2019 before Patch 1", "AVEVA Edge 2019.1"],
        description=(
            "AVEVA Edge industrial HMI software contains an indirect object reference "
            "vulnerability allowing an authenticated attacker to access sensitive "
            "engineering data, controller credentials, and historical logs without "
            "proper authorization, exposing forensically significant artifacts."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2019-13161",
            "https://www.aveva.com/",
        ],
    ),
    CveRecord(
        cve_id="CVE-2021-39806",
        published="2021-09-14",
        cvss_version="3.1",
        cvss_score=8.8,
        cvss_severity="HIGH",
        cwe_ids=["CWE-94"],
        category="mobile",
        affected_products=["Android framework before 2021-10-01 security patch"],
        description=(
            "The Android framework contains an unsafe deserialization vulnerability "
            "allowing an attacker with code execution in the MediaCodec process to "
            "gain arbitrary code execution with elevated privileges through multiple "
            "Intent-based Broadcast Receiver triggers."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2021-39806",
            "https://source.android.com/security/bulletin",
        ],
    ),
    CveRecord(
        cve_id="CVE-2015-6610",
        published="2015-10-05",
        cvss_version="2.0",
        cvss_score=9.3,
        cvss_severity="HIGH",
        cwe_ids=["CWE-94"],
        category="mobile",
        affected_products=["Android before 2015-10-05 security patch"],
        description=(
            "Multiple integer overflow vulnerabilities in the Stagefright media player "
            "in Android allow remote attackers to execute arbitrary code via specially "
            "crafted media files, affecting millions of Android devices without any "
            "user interaction required."
        ),
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2015-6610",
            "https://source.android.com/security/bulletin/2015-10-01",
        ],
    ),
)


def _classify(record: CveRecord) -> CveRecord:
    """Fill in a category from CWE hints when the record has none set."""
    if record.category in CATEGORIES:
        return record
    for cwe in record.cwe_ids:
        hint = CWE_CATEGORY_HINTS.get(cwe)
        if hint is not None:
            return CveRecord(**{**record.to_mapping(), "category": hint})
    return CveRecord(**{**record.to_mapping(), "category": "web"})


class SnapshotCveSource:
    """Offline, deterministic CVE source backed by a bundled curated fixture.

    This is the default and test backend: stdlib-only, no network, and the
    same input arguments always produce the same output.
    """

    def __init__(self, records: list[CveRecord] | None = None) -> None:
        self._records: list[CveRecord] = (
            list(records) if records is not None else list(_BUNDLED_RECORDS)
        )

    def fetch(
        self,
        *,
        category: str | None = None,
        min_cvss: float = 0.0,
        published_after: str | None = None,
        keyword: str | None = None,
        limit: int = 20,
    ) -> list[CveRecord]:
        return _filter_records(
            self._records,
            category=category,
            min_cvss=min_cvss,
            published_after=published_after,
            keyword=keyword,
            limit=limit,
        )

    def get(self, cve_id: str) -> CveRecord | None:
        for record in self._records:
            if record.cve_id == cve_id:
                return record
        return None


# --- NVD live backend ---------------------------------------------------------

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdFetcher(Protocol):
    def __call__(self, url: str, headers: dict[str, str], timeout: int) -> bytes: ...


def _default_nvd_fetcher(url: str, headers: dict[str, str], timeout: int) -> bytes:
    import urllib.request

    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return response.read()


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _extract_cvss(metrics: dict) -> tuple[str, float, str]:
    """Pull (version, score, severity) from an NVD 2.0 ``metrics`` block.

    Prefers the highest available CVSS version (3.1 -> 3.0 -> 2.0).
    """
    for key, version in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key) or []
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = float(cvss_data.get("baseScore", 0.0))
            severity = str(
                entries[0].get("baseSeverity") or cvss_data.get("baseSeverity") or ""
            ).upper() or _severity_from_score(score)
            return version, score, severity
    return "0.0", 0.0, "NONE"


def _extract_cwe_ids(weaknesses: list[dict]) -> list[str]:
    cwe_ids: list[str] = []
    for weakness in weaknesses or []:
        for desc in weakness.get("description", []) or []:
            value = desc.get("value")
            if value and value.startswith("CWE-") and value not in cwe_ids:
                cwe_ids.append(value)
    return cwe_ids


def _extract_description(descriptions: list[dict]) -> str:
    for desc in descriptions or []:
        if desc.get("lang") == "en":
            return str(desc.get("value", ""))
    if descriptions:
        return str(descriptions[0].get("value", ""))
    return ""


def _extract_affected_products(configurations: list[dict]) -> list[str]:
    products: list[str] = []
    for config in configurations or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria")
                if criteria and criteria not in products:
                    products.append(criteria)
    return products


def _category_for_cwe_ids(cwe_ids: list[str]) -> str:
    for cwe in cwe_ids:
        hint = CWE_CATEGORY_HINTS.get(cwe)
        if hint is not None:
            return hint
    return "web"


def cve_record_from_nvd_json(item: dict) -> CveRecord:
    """Parse a single ``vulnerabilities[].cve`` element from an NVD 2.0 response."""
    cve = item.get("cve", item)
    cve_id = str(cve.get("id", ""))
    published = str(cve.get("published", ""))
    metrics = cve.get("metrics", {}) or {}
    cvss_version, cvss_score, cvss_severity = _extract_cvss(metrics)
    cwe_ids = _extract_cwe_ids(cve.get("weaknesses", []) or [])
    description = _extract_description(cve.get("descriptions", []) or [])
    affected_products = _extract_affected_products(cve.get("configurations", []) or [])
    references = [
        str(ref.get("url", ""))
        for ref in cve.get("references", []) or []
        if ref.get("url")
    ]
    return CveRecord(
        cve_id=cve_id,
        published=published,
        cvss_version=cvss_version,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        cwe_ids=cwe_ids,
        category=_category_for_cwe_ids(cwe_ids),
        affected_products=affected_products,
        description=description,
        references=references,
    )


def _parse_nvd_response(raw: bytes) -> list[CveRecord]:
    data = json.loads(raw.decode("utf-8"))
    vulnerabilities = data.get("vulnerabilities", []) or []
    return [cve_record_from_nvd_json(item) for item in vulnerabilities]


class NvdCveSource:
    """Live NVD 2.0 REST API backend.

    Uses stdlib ``urllib.request`` by default (lazily imported, only invoked
    on live calls). Pass a fake ``fetcher`` for deterministic, network-free
    tests.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = NVD_BASE_URL,
        timeout: int = 20,
        fetcher: NvdFetcher | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url
        self._timeout = timeout
        self._fetcher = fetcher or _default_nvd_fetcher

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    def fetch(
        self,
        *,
        category: str | None = None,
        min_cvss: float = 0.0,
        published_after: str | None = None,
        keyword: str | None = None,
        limit: int = 20,
    ) -> list[CveRecord]:
        params: list[str] = [f"resultsPerPage={max(limit, 1)}"]
        if keyword:
            import urllib.parse

            params.append(f"keywordSearch={urllib.parse.quote(keyword)}")
        if min_cvss > 0.0:
            params.append(f"cvssV3Severity={_severity_from_score(min_cvss)}")
        if published_after:
            params.append(f"pubStartDate={published_after}")
        url = f"{self._base_url}?{'&'.join(params)}"
        raw = self._fetcher(url, self._headers(), self._timeout)
        records = _parse_nvd_response(raw)
        return _filter_records(
            records,
            category=category,
            min_cvss=min_cvss,
            published_after=published_after,
            keyword=None,  # already applied server-side via keywordSearch
            limit=limit,
        )

    def get(self, cve_id: str) -> CveRecord | None:
        url = f"{self._base_url}?cveId={cve_id}"
        raw = self._fetcher(url, self._headers(), self._timeout)
        records = _parse_nvd_response(raw)
        for record in records:
            if record.cve_id == cve_id:
                return record
        return records[0] if records else None


# --- Caching wrapper -----------------------------------------------------------


class Clock(Protocol):
    def __call__(self) -> float: ...


@dataclass
class _CacheEntry:
    expires_at: float
    records: list[dict[str, object]]


class CachingCveSource:
    """Wraps another ``CveSource`` with a TTL file cache.

    Cache entries are keyed by the normalized query arguments and stored as
    JSON files under ``cache_dir``. The clock is injectable so tests can
    control expiry deterministically without sleeping.
    """

    def __init__(
        self,
        source: CveSource,
        cache_dir: Path,
        ttl_seconds: float = 3600.0,
        clock: Clock | None = None,
    ) -> None:
        self._source = source
        self._cache_dir = Path(cache_dir)
        self._ttl_seconds = ttl_seconds
        self._clock = clock or time.time

    def _cache_path(self, key: str) -> Path:
        safe_key = "".join(c if c.isalnum() or c in "-_" else "_" for c in key)
        return self._cache_dir / f"{safe_key}.json"

    def _read_cache(self, key: str) -> list[CveRecord] | None:
        path = self._cache_path(key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if payload.get("expires_at", 0.0) < self._clock():
            return None
        return [CveRecord(**item) for item in payload.get("records", [])]

    def _write_cache(self, key: str, records: list[CveRecord]) -> None:
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._cache_path(key)
        payload = {
            "expires_at": self._clock() + self._ttl_seconds,
            "records": [r.to_mapping() for r in records],
        }
        path.write_text(json.dumps(payload), encoding="utf-8")

    def fetch(
        self,
        *,
        category: str | None = None,
        min_cvss: float = 0.0,
        published_after: str | None = None,
        keyword: str | None = None,
        limit: int = 20,
    ) -> list[CveRecord]:
        key = f"fetch-{category}-{min_cvss}-{published_after}-{keyword}-{limit}"
        cached = self._read_cache(key)
        if cached is not None:
            return cached
        records = self._source.fetch(
            category=category,
            min_cvss=min_cvss,
            published_after=published_after,
            keyword=keyword,
            limit=limit,
        )
        self._write_cache(key, records)
        return records

    def get(self, cve_id: str) -> CveRecord | None:
        key = f"get-{cve_id}"
        cached = self._read_cache(key)
        if cached is not None:
            return cached[0] if cached else None
        record = self._source.get(cve_id)
        self._write_cache(key, [record] if record is not None else [])
        return record


# --- Factory -------------------------------------------------------------------


def get_source(name: str = "snapshot", **kwargs: object) -> CveSource:
    if name == "snapshot":
        return SnapshotCveSource(**kwargs)  # type: ignore[arg-type]
    if name == "nvd":
        return NvdCveSource(**kwargs)  # type: ignore[arg-type]
    raise ValueError(f"unknown CVE source: {name}")
