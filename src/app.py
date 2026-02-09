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
import requests
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import BaseAsset, AssetField
from soar_sdk.logging import getLogger
from .apivoid_consts import *
from .models.outputs.certificate.get_cert_info import (
    CertificateDetails,
    CertificateSummary,
    GetCertInfoParams,
)
from .models.outputs.domain.domain_reputation import (
    BlacklistEngine,
    DomainReputationDetails,
    DomainReputationParams,
    DomainReputationSummary,
)
from .models.outputs.ip.ip_reputation import (
    IpBlacklistEngine,
    IpReputationDetails,
    IpReputationParams,
    IpReputationSummary,
)

logger = getLogger()


class Asset(BaseAsset):
    """APIVoid v2 API configuration"""

    server_url: str = AssetField(
        description="API Server URL (e.g., https://api.apivoid.com)",
        required=True,
    )
    api_key: str = AssetField(
        description="API Key for authentication",
        sensitive=True,
        required=True,
    )


app = App(
    name="APIvoid v2",
    app_type="reputation",
    logo="logo_apivoid.svg",
    logo_dark="logo_apivoid_dark.svg",
    product_vendor="APIVoid",
    product_name="APIVoid",
    publisher="Splunk Inc.",
    appid="ffffffff-ffff-4fff-afff-ffffffffffff",
    fips_compliant=False,
    asset_cls=Asset,
)


# Helper function for API requests
def _make_api_request(endpoint: str, asset: Asset, params: dict) -> dict:
    """
    Make a REST API call to APIVoid v2 API.

    :param endpoint: API endpoint (e.g., 'v2/ssl-info')
    :param asset: Asset configuration
    :param params: Request parameters to send as JSON body
    :return: Response JSON data
    :raises Exception: If request fails or API returns an error
    """
    url = f"{asset.server_url.rstrip('/')}/{endpoint}"
    headers = {
        HEADER_API_KEY: asset.api_key,
        HEADER_CONTENT_TYPE: CONTENT_TYPE_JSON,
    }

    logger.debug(MSG_MAKING_API_REQUEST.format(url))

    try:
        response = requests.post(
            url, json=params, headers=headers, timeout=DEFAULT_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()

        # Check for API errors
        if data.get(KEY_ERROR):
            error_msg = data.get(KEY_ERROR)
            logger.error(ERROR_API_ERROR.format(error_msg))
            raise Exception(ERROR_API_ERROR.format(error_msg))

        return data

    except requests.exceptions.Timeout:
        raise Exception(ERROR_TIMEOUT.format(DEFAULT_TIMEOUT)) from None
    except requests.exceptions.ConnectionError as e:
        raise Exception(ERROR_CONNECTION.format(str(e))) from None
    except requests.exceptions.HTTPError as e:
        raise Exception(
            ERROR_HTTP.format(e.response.status_code, e.response.text)
        ) from None
    except requests.exceptions.RequestException as e:
        raise Exception(ERROR_REQUEST.format(str(e))) from None
    except ValueError as e:
        raise Exception(ERROR_INVALID_JSON.format(str(e))) from None


# Test Connectivity Action
@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Test connectivity to APIVoid v2 API"""
    logger.info(MSG_CONNECTING_TO_SERVER)

    try:
        # Test API connectivity with SSL Info endpoint
        params = {"host": TEST_DOMAIN}
        data = _make_api_request(ENDPOINT_SSL_INFO, asset, params)

        # Validate response structure
        if not data.get(KEY_CERTIFICATE):
            raise Exception(ERROR_UNEXPECTED_RESPONSE)

        logger.info(MSG_TEST_CONNECTIVITY_PASSED)

    except Exception as e:
        logger.error(MSG_TEST_CONNECTIVITY_FAILED)
        raise Exception(f"{MSG_TEST_CONNECTIVITY_FAILED}: {e!s}") from e


# Get Certificate Info Action
@app.action(
    description="Query certificate information for a domain",
    action_type="investigate",
    summary_type=CertificateSummary,
    render_as="table",
)
def get_cert_info(
    param: GetCertInfoParams, soar: SOARClient[CertificateSummary], asset: Asset
) -> CertificateDetails:
    """Get certificate information for a domain"""
    logger.info(MSG_QUERYING_CERT_INFO.format(param.domain))

    params = {"host": param.domain}
    data = _make_api_request(ENDPOINT_SSL_INFO, asset, params)

    # Validate response structure
    cert = data.get(KEY_CERTIFICATE)
    if not cert:
        raise Exception(ERROR_NO_CERT_DATA)

    # Extract certificate data
    cert_found = cert.get("found", False)
    details = cert.get("details", {})
    subject = details.get("subject", {})
    issuer = details.get("issuer", {})
    public_key = details.get("public_key", {})
    signature = details.get("signature", {})
    validity = details.get("validity", {})
    extensions = details.get("extensions", {})

    # Convert array fields to comma-separated strings for SOAR compatibility
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

    # Convert organization_unit arrays to comma-separated strings
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

    # Convert street arrays to comma-separated strings
    subject_street_str = (
        ", ".join(subject.get("street", [])) if subject.get("street") else None
    )

    # Convert authority_info array to formatted string
    authority_info_list = details.get("authority_info", [])
    authority_info_str = None
    if authority_info_list:
        authority_info_parts = [
            f"{item.get('method')}: {item.get('location')}"
            for item in authority_info_list
        ]
        authority_info_str = ", ".join(authority_info_parts)

    result = CertificateDetails(
        # Basic Info
        certificate_found=cert_found,
        host=data.get("host", param.domain),
        elapsed_ms=data.get("elapsed_ms"),
        # Certificate Status
        expired=cert.get("expired"),
        valid=cert.get("valid"),
        valid_peer=cert.get("valid_peer"),
        name_match=cert.get("name_match"),
        blacklisted=cert.get("blacklisted"),
        revoked=cert.get("revoked"),
        # Certificate Metadata
        certificate_type=cert.get("type"),
        fingerprint_sha1=cert.get("fingerprint_sha1"),
        fingerprint_sha256=cert.get("fingerprint_sha256"),
        deprecated_issuer=cert.get("deprecated_issuer"),
        certificate_hash=details.get("hash"),
        certificate_version=details.get("version"),
        # Subject Details
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
        # Issuer Details
        issuer_common_name=issuer.get("common_name"),
        issuer_organization=issuer.get("organization"),
        issuer_organization_unit=issuer_org_unit_str,
        issuer_country=issuer.get("country"),
        issuer_state=issuer.get("state"),
        issuer_location=issuer.get("location"),
        # Public Key
        public_key_algorithm=public_key.get("algorithm"),
        public_key_size=public_key.get("size"),
        # Signature Details
        signature_serial=signature.get("serial"),
        signature_serial_hex=signature.get("serial_hex"),
        signature_type=signature.get("type"),
        # Validity Details
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
        # Certificate Authority Info
        certificate_authority=details.get("certificate_authority"),
        authority_key_id=details.get("authority_key_id"),
        subject_key_id=details.get("subject_key_id"),
        key_usages=key_usages_str,
        extended_key_usages=extended_key_usages_str,
        crl_endpoints=crl_endpoints_str,
        authority_info=authority_info_str,
    )

    # Set summary and message
    summary = CertificateSummary(certificate_found=cert_found, domain=param.domain)
    soar.set_summary(summary)
    soar.set_message(summary.get_message())

    logger.info(MSG_CERT_INFO_SUCCESS.format(param.domain))
    return result


# IP Reputation Action
@app.action(
    description="Check IP address reputation against blacklists",
    action_type="investigate",
    summary_type=IpReputationSummary,
    render_as="table",
)
def ip_reputation(
    param: IpReputationParams, soar: SOARClient[IpReputationSummary], asset: Asset
) -> IpReputationDetails:
    """Check IP address reputation against multiple blacklist engines"""
    logger.info(MSG_QUERYING_IP_REP.format(param.ip))

    params = {"ip": param.ip}
    data = _make_api_request(ENDPOINT_IP_REPUTATION, asset, params)

    # Extract blacklist data
    blacklists = data.get(KEY_BLACKLISTS)
    if not blacklists:
        raise Exception(ERROR_NO_BLACKLIST_DATA)

    # Extract individual engine results
    engines_list = []
    engines_data = blacklists.get("engines", {})
    for engine_name, engine_info in engines_data.items():
        engines_list.append(
            IpBlacklistEngine(
                name=engine_info.get("name", engine_name),
                detected=engine_info.get("detected"),
                reference=engine_info.get("reference"),
                elapsed_ms=str(engine_info.get("elapsed_ms", "0.00")),
            )
        )

    # Extract nested objects
    information = data.get("information", {})
    asn_data = data.get("asn", {})
    anonymity = data.get("anonymity", {})
    risk_score = data.get("risk_score", {})

    result = IpReputationDetails(
        # Basic IP Info
        ip=data.get("ip"),
        version=data.get("version"),
        # Blacklist Results
        detections=blacklists.get("detections"),
        engines_count=blacklists.get("engines_count"),
        detection_rate=blacklists.get("detection_rate"),
        scan_time_ms=str(blacklists.get("scan_time_ms", "0.00")),
        elapsed_ms=data.get("elapsed_ms"),
        engines=engines_list,
        # Geolocation (from information)
        reverse_dns=information.get("reverse_dns"),
        continent_code=information.get("continent_code"),
        continent_name=information.get("continent_name"),
        country_code=information.get("country_code"),
        country_name=information.get("country_name"),
        region_name=information.get("region_name"),
        city_name=information.get("city_name"),
        latitude=information.get("latitude"),
        longitude=information.get("longitude"),
        isp=information.get("isp"),
        # Bot & Service Detection
        is_bogon=information.get("is_bogon"),
        is_spamhaus_drop=information.get("is_spamhaus_drop"),
        is_fake_bot=information.get("is_fake_bot"),
        is_google_bot=information.get("is_google_bot"),
        is_search_engine_bot=information.get("is_search_engine_bot"),
        is_public_dns=information.get("is_public_dns"),
        cloud_provider=information.get("cloud_provider"),
        aws_service=information.get("aws_service"),
        is_google_service=information.get("is_google_service"),
        is_satellite=information.get("is_satellite"),
        # ASN Details
        asn=asn_data.get("asn"),
        asname=asn_data.get("asname"),
        asn_route=asn_data.get("route"),
        asn_org=asn_data.get("org"),
        asn_country_code=asn_data.get("country_code"),
        abuse_email=asn_data.get("abuse_email"),
        asn_domain=asn_data.get("domain"),
        asn_type=asn_data.get("type"),
        # Anonymity Detection
        is_proxy=anonymity.get("is_proxy"),
        is_webproxy=anonymity.get("is_webproxy"),
        is_residential_proxy=anonymity.get("is_residential_proxy"),
        is_vpn=anonymity.get("is_vpn"),
        is_hosting=anonymity.get("is_hosting"),
        is_relay=anonymity.get("is_relay"),
        is_tor=anonymity.get("is_tor"),
        # Risk Score
        risk_score=risk_score.get("result"),
    )

    # Set summary and message
    summary = IpReputationSummary(
        detections=result.detections,
        engines_count=result.engines_count,
        detection_rate=result.detection_rate,
    )
    soar.set_summary(summary)
    soar.set_message(summary.get_message())

    logger.info(
        MSG_IP_REP_COMPLETED.format(param.ip, result.detections, result.engines_count)
    )
    return result


# Domain Reputation Action
@app.action(
    description="Check domain reputation against blacklists",
    action_type="investigate",
    summary_type=DomainReputationSummary,
    render_as="table",
)
def domain_reputation(
    param: DomainReputationParams,
    soar: SOARClient[DomainReputationSummary],
    asset: Asset,
) -> DomainReputationDetails:
    """Check domain reputation against multiple blacklist engines"""
    logger.info(MSG_QUERYING_DOMAIN_REP.format(param.domain))

    params = {"host": param.domain}
    data = _make_api_request(ENDPOINT_DOMAIN_REPUTATION, asset, params)

    # Extract blacklist data
    blacklists = data.get(KEY_BLACKLISTS)
    if not blacklists:
        raise Exception(ERROR_NO_BLACKLIST_DATA)

    # Extract individual engine results
    engines_list = []
    engines_data = blacklists.get("engines", {})
    for engine_name, engine_info in engines_data.items():
        engines_list.append(
            BlacklistEngine(
                name=engine_info.get("name", engine_name),
                detected=engine_info.get("detected"),
                confidence=engine_info.get("confidence"),
                reference=engine_info.get("reference"),
                elapsed_ms=str(engine_info.get("elapsed_ms", "0.00")),
            )
        )

    # Extract v2 nested objects
    server_details = data.get("server_details", {})
    category = data.get("category", {})
    security_checks = data.get("security_checks", {})
    domain_parts = data.get("domain_parts", {})
    risk_score = data.get("risk_score", {})

    result = DomainReputationDetails(
        # Basic Domain Info
        host=data.get("host", param.domain),
        # Blacklist Results
        detections=blacklists.get("detections"),
        engines_count=blacklists.get("engines_count"),
        detection_rate=blacklists.get("detection_rate"),
        scan_time_ms=str(blacklists.get("scan_time_ms", "0.00")),
        elapsed_ms=data.get("elapsed_ms"),
        engines=engines_list,
        # Server Details
        server_ip=server_details.get("ip"),
        reverse_dns=server_details.get("reverse_dns"),
        continent_code=server_details.get("continent_code"),
        continent_name=server_details.get("continent_name"),
        country_code=server_details.get("country_code"),
        country_name=server_details.get("country_name"),
        region_name=server_details.get("region_name"),
        city_name=server_details.get("city_name"),
        latitude=server_details.get("latitude"),
        longitude=server_details.get("longitude"),
        isp=server_details.get("isp"),
        asn=server_details.get("asn"),
        # Category
        is_free_hosting=category.get("is_free_hosting"),
        is_anonymizer=category.get("is_anonymizer"),
        is_url_shortener=category.get("is_url_shortener"),
        is_free_dynamic_dns=category.get("is_free_dynamic_dns"),
        is_code_sandbox=category.get("is_code_sandbox"),
        is_form_builder=category.get("is_form_builder"),
        is_free_file_sharing=category.get("is_free_file_sharing"),
        is_pastebin=category.get("is_pastebin"),
        # Security Checks
        is_most_abused_tld=security_checks.get("is_most_abused_tld"),
        is_suspicious_homoglyph=security_checks.get("is_suspicious_homoglyph"),
        is_possible_typosquatting=security_checks.get("is_possible_typosquatting"),
        website_popularity=security_checks.get("website_popularity"),
        is_risky_category=security_checks.get("is_risky_category"),
        # Domain Parts
        root_domain=domain_parts.get("root_domain"),
        subdomain=domain_parts.get("subdomain"),
        tld=domain_parts.get("tld"),
        # Risk Score
        risk_score=risk_score.get("result"),
    )

    # Set summary and message
    summary = DomainReputationSummary(
        detections=result.detections,
        engines_count=result.engines_count,
        detection_rate=result.detection_rate,
    )
    soar.set_summary(summary)
    soar.set_message(summary.get_message())

    logger.info(
        MSG_DOMAIN_REP_COMPLETED.format(result.detections, result.engines_count)
    )
    return result


if __name__ == "__main__":
    app.cli()
