# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..apivoid_consts import *
from ..asset import Asset
from ..rest_api_client import _make_api_request

logger = getLogger()


class GetCertInfoParams(Params):
    """Parameters for get_cert_info action input"""

    domain: str = Param(
        description="Domain to query (e.g., google.com)",
        required=True,
        primary=True,
        cef_types=["domain", "url"],
        column_name="Domain",
    )


class CertificateDetails(ActionOutput):
    """Certificate information output"""

    # Basic Info
    certificate_found: bool = OutputField(
        cef_types=["certificate"],
        example_values=[True, False],
        column_name="Certificate Found",
    )
    host: str = OutputField(
        cef_types=["domain", "host name"],
        example_values=["google.com"],
        column_name="Host",
    )
    elapsed_ms: int | None = OutputField(
        example_values=[45, 123, 87],
        column_name="Response Time (ms)",
    )

    # Certificate Status
    expired: bool | None = OutputField(
        example_values=[True, False],
        column_name="Certificate Expired",
    )
    valid: bool | None = OutputField(
        example_values=[True, False],
    )
    valid_peer: bool | None = OutputField(
        example_values=[True, False],
    )
    name_match: bool | None = OutputField(
        example_values=[True, False],
    )
    blacklisted: bool | None = OutputField(
        example_values=[True, False],
    )
    revoked: bool | None = OutputField(
        example_values=[True, False],
    )

    # Certificate Metadata
    certificate_type: str | None = OutputField(
        example_values=[
            "Domain Validation",
            "Extended Validation",
            "Organization Validation",
        ],
    )
    fingerprint_sha1: str | None = OutputField(
        cef_types=["sha1", "hash"],
        example_values=[
            "f81e3171fa085bc04c83b6644b9f229f0cba8e57"  # pragma: allowlist secret
        ],
    )
    fingerprint_sha256: str | None = OutputField(
        cef_types=["sha256", "hash"],
        example_values=[
            "faf941ad6b7339463bcea590e77e39f7930a168eb6d130d79c3be12c5de83894"  # pragma: allowlist secret
        ],
    )
    deprecated_issuer: bool | None = OutputField(
        example_values=[True, False],
    )

    # Certificate Details Hash
    certificate_hash: str | None = OutputField(
        cef_types=["hash"],
        example_values=["d5b02a29"],
    )

    # Certificate Version
    certificate_version: str | None = OutputField(
        example_values=["2", "3"],
    )

    # Subject Details
    subject_name: str | None = OutputField(
        example_values=[
            "/C=US/ST=California/L=Mountain View/O=Google LLC/CN=*.google.com"
        ],
    )
    subject_common_name: str | None = OutputField(
        cef_types=["domain"],
        example_values=["*.google.com", "paypal.com"],
    )
    subject_alternative_names: str | None = OutputField(
        example_values=["DNS:*.google.com, DNS:google.com, DNS:*.youtube.com"],
    )
    subject_organization: str | None = OutputField(
        example_values=["Google LLC", "PayPal, Inc."],
    )
    subject_organization_unit: str | None = OutputField(
        example_values=["IT Department", ""],
    )
    subject_category: str | None = OutputField(
        example_values=["Private Organization", "Business Entity"],
    )
    subject_country: str | None = OutputField(
        example_values=["US", "GB"],
    )
    subject_state: str | None = OutputField(
        example_values=["California", "Delaware"],
    )
    subject_location: str | None = OutputField(
        example_values=["Mountain View", "San Jose"],
    )
    subject_postal_code: str | None = OutputField(
        example_values=["94043", ""],
    )
    subject_street: str | None = OutputField(
        example_values=["1600 Amphitheatre Parkway", ""],
    )
    subject_serial_number: str | None = OutputField(
        example_values=["3014267"],
    )
    subject_inc_country: str | None = OutputField(
        example_values=["US", "DE"],
    )
    subject_inc_state: str | None = OutputField(
        example_values=["Delaware", "Nevada"],
    )

    # Issuer Details
    issuer_common_name: str | None = OutputField(
        example_values=["Google Internet Authority G3", "DigiCert EV RSA CA G2"],
        column_name="Issuer Name",
    )
    issuer_organization: str | None = OutputField(
        example_values=["Google Trust Services", "DigiCert Inc"],
        column_name="Issuer Organization",
    )
    issuer_organization_unit: str | None = OutputField(
        example_values=["", "Organization Unit"],
    )
    issuer_country: str | None = OutputField(
        example_values=["US", "GB"],
    )
    issuer_state: str | None = OutputField(
        example_values=["California", ""],
    )
    issuer_location: str | None = OutputField(
        example_values=["Mountain View", ""],
    )

    # Public Key
    public_key_algorithm: str | None = OutputField(
        example_values=["RSA", "ECDSA"],
    )
    public_key_size: int | None = OutputField(
        example_values=[2048, 4096, 256],
    )

    # Signature Details
    signature_serial: str | None = OutputField(
        example_values=[
            "154395212770671185670675998830856977631"
        ],  # pragma: allowlist secret
    )
    signature_serial_hex: str | None = OutputField(
        cef_types=["md5", "hash"],
        example_values=["74276FB4EDD2D5219515679EAE273CDF"],  # pragma: allowlist secret
    )
    signature_type: str | None = OutputField(
        example_values=["RSA-SHA256", "SHA256-RSA", "SHA384-RSA"],
    )

    # Validity Details
    valid_from: str | None = OutputField(
        example_values=[
            "Fri, 01 Mar 2019 09:43:57 GMT",
            "Mon, 26 Aug 2024 00:00:00 UTC",
        ],
        column_name="Valid From",
    )
    valid_to: str | None = OutputField(
        example_values=[
            "Fri, 24 May 2019 09:25:00 GMT",
            "Mon, 25 Aug 2025 23:59:59 UTC",
        ],
        column_name="Valid To",
    )
    valid_from_timestamp: int | None = OutputField(
        example_values=[1551433437, 1724630400],
    )
    valid_to_timestamp: int | None = OutputField(
        example_values=[1558689900, 1756166399],
    )
    days_left: int | None = OutputField(
        example_values=[60, 30, 90, 269],
    )

    # Extensions (flattened from nested structure)
    extensions_authority_info_access: str | None = OutputField(
        example_values=[
            "CA Issuers - URI:http://pki.goog/gsr2/GTSGIAG3.crt\nOCSP - URI:http://ocsp.pki.goog/GTSGIAG3\n"
        ],
    )
    extensions_authority_key_identifier: str | None = OutputField(
        example_values=[
            "keyid:77:C2:B8:50:9A:67:76:76:B1:2D:C2:86:D0:83:A0:7E:A6:7E:BA:4B\n"
        ],
    )
    extensions_subject_key_identifier: str | None = OutputField(
        example_values=["AD:04:58:61:3A:F6:D7:C7:56:6B:20:0B:58:09:79:11:22:F7:69:B6"],
    )
    extensions_basic_constraints: str | None = OutputField(
        example_values=["CA:FALSE", "CA:TRUE"],
    )
    extensions_certificate_policies: str | None = OutputField(
        example_values=["Policy: 1.3.6.1.4.1.11129.2.5.3\nPolicy: 2.23.140.1.2.2\n"],
    )
    extensions_crl_distribution_points: str | None = OutputField(
        example_values=["\nFull Name:\n  URI:http://crl.pki.goog/GTSGIAG3.crl\n"],
    )
    extensions_key_usage: str | None = OutputField(
        example_values=["Digital Signature", "Digital Signature, Key Encipherment"],
    )
    extensions_extended_key_usage: str | None = OutputField(
        example_values=[
            "TLS Web Server Authentication",
            "Server Authentication, Client Authentication",
        ],
    )

    # Certificate Authority Info
    certificate_authority: bool | None = OutputField(
        example_values=[True, False],
    )
    authority_key_id: str | None = OutputField(
        example_values=[
            "301680146a4e50bf98689d5b7b2075d45901794866923206"  # pragma: allowlist secret
        ],
    )
    subject_key_id: str | None = OutputField(
        example_values=[
            "04148d939fbf9c7cf8ba64066baa73bb814351b7dc41"  # pragma: allowlist secret
        ],
    )

    # Key Usages (comma-separated)
    key_usages: str | None = OutputField(
        example_values=["Digital Signature, Key Encipherment"],
    )
    extended_key_usages: str | None = OutputField(
        example_values=["Server Authentication, Client Authentication"],
    )
    crl_endpoints: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "http://crl3.digicert.com/DigiCertEVRSACAG2.crl, http://crl4.digicert.com/DigiCertEVRSACAG2.crl"
        ],
    )

    # Authority Info (formatted string from array)
    authority_info: str | None = OutputField(
        example_values=[
            "OCSP: http://o.pki.goog/wr2, CA Issuers: http://i.pki.goog/wr2.crt"
        ],
    )


class CertificateSummary(ActionOutput):
    """Summary for certificate info action"""

    certificate_found: bool = OutputField(
        example_values=[True, False],
    )
    domain: str = OutputField(
        example_values=["google.com", "example.com"],
    )

    def get_message(self) -> str:
        """Generate summary message following official SOAR SDK pattern"""
        return f"Received Certificate information for domain {self.domain}"


def get_cert_info(
    param: GetCertInfoParams,
    soar: SOARClient[CertificateSummary],
    asset: Asset,
) -> CertificateDetails:
    """Get certificate information for a domain."""
    logger.info(MSG_QUERYING_CERT_INFO.format(param.domain))

    params = {"host": param.domain}
    data = _make_api_request(ENDPOINT_SSL_INFO, asset, params)

    cert = data.get(KEY_CERTIFICATE)
    if not cert:
        raise Exception(ERROR_NO_CERT_DATA)

    cert_found = cert.get("found", False)
    details = cert.get("details", {})
    subject = details.get("subject", {})
    issuer = details.get("issuer", {})
    public_key = details.get("public_key", {})
    signature = details.get("signature", {})
    validity = details.get("validity", {})
    extensions = details.get("extensions", {})

    key_usages_str = (
        ", ".join(details.get("key_usages", [])) if details.get("key_usages") else None
    )
    extended_key_usages_str = (
        ", ".join(details.get("extended_key_usages", []))
        if details.get("extended_key_usages")
        else None
    )
    crl_endpoints_str = (
        ", ".join(details.get("crl_endpoints", []))
        if details.get("crl_endpoints")
        else None
    )

    subject_org_unit_str = (
        ", ".join(subject.get("organization_unit", []))
        if subject.get("organization_unit")
        else None
    )
    issuer_org_unit_str = (
        ", ".join(issuer.get("organization_unit", []))
        if issuer.get("organization_unit")
        else None
    )

    subject_street_str = (
        ", ".join(subject.get("street", [])) if subject.get("street") else None
    )

    authority_info_list = details.get("authority_info", [])
    authority_info_str = None
    if authority_info_list:
        authority_info_parts = [
            f"{item.get('method')}: {item.get('location')}"
            for item in authority_info_list
        ]
        authority_info_str = ", ".join(authority_info_parts)

    result = CertificateDetails(
        certificate_found=cert_found,
        host=data.get("host", param.domain),
        elapsed_ms=data.get("elapsed_ms"),
        expired=cert.get("expired"),
        valid=cert.get("valid"),
        valid_peer=cert.get("valid_peer"),
        name_match=cert.get("name_match"),
        blacklisted=cert.get("blacklisted"),
        revoked=cert.get("revoked"),
        certificate_type=cert.get("type"),
        fingerprint_sha1=cert.get("fingerprint_sha1"),
        fingerprint_sha256=cert.get("fingerprint_sha256"),
        deprecated_issuer=cert.get("deprecated_issuer"),
        certificate_hash=details.get("hash"),
        certificate_version=details.get("version"),
        subject_name=subject.get("name"),
        subject_common_name=subject.get("common_name"),
        subject_alternative_names=subject.get("alternative_names"),
        subject_organization=subject.get("organization"),
        subject_organization_unit=subject_org_unit_str,
        subject_category=subject.get("category"),
        subject_country=subject.get("country"),
        subject_state=subject.get("state"),
        subject_location=subject.get("location"),
        subject_postal_code=subject.get("postal_code"),
        subject_street=subject_street_str,
        subject_serial_number=subject.get("serial_number"),
        subject_inc_country=subject.get("inc_country"),
        subject_inc_state=subject.get("inc_state"),
        issuer_common_name=issuer.get("common_name"),
        issuer_organization=issuer.get("organization"),
        issuer_organization_unit=issuer_org_unit_str,
        issuer_country=issuer.get("country"),
        issuer_state=issuer.get("state"),
        issuer_location=issuer.get("location"),
        public_key_algorithm=public_key.get("algorithm"),
        public_key_size=public_key.get("size"),
        signature_serial=signature.get("serial"),
        signature_serial_hex=signature.get("serial_hex"),
        signature_type=signature.get("type"),
        valid_from=validity.get("valid_from"),
        valid_to=validity.get("valid_to"),
        valid_from_timestamp=validity.get("valid_from_timestamp"),
        valid_to_timestamp=validity.get("valid_to_timestamp"),
        days_left=validity.get("days_left"),
        extensions_authority_info_access=extensions.get("authority_info_access"),
        extensions_authority_key_identifier=extensions.get("authority_key_identifier"),
        extensions_subject_key_identifier=extensions.get("subject_key_identifier"),
        extensions_basic_constraints=extensions.get("basic_constraints"),
        extensions_certificate_policies=extensions.get("certificate_policies"),
        extensions_crl_distribution_points=extensions.get("crl_distribution_points"),
        extensions_key_usage=extensions.get("key_usage"),
        extensions_extended_key_usage=extensions.get("extended_key_usage"),
        certificate_authority=details.get("certificate_authority"),
        authority_key_id=details.get("authority_key_id"),
        subject_key_id=details.get("subject_key_id"),
        key_usages=key_usages_str,
        extended_key_usages=extended_key_usages_str,
        crl_endpoints=crl_endpoints_str,
        authority_info=authority_info_str,
    )

    summary = CertificateSummary(certificate_found=cert_found, domain=param.domain)
    soar.set_summary(summary)
    soar.set_message(summary.get_message())

    logger.info(MSG_CERT_INFO_SUCCESS.format(param.domain))
    return result
