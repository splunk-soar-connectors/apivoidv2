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


class DomainReputationParams(Params):
    """Parameters for domain reputation action input"""

    domain: str = Param(
        description="Domain to check reputation",
        required=True,
        primary=True,
        cef_types=["domain", "url"],
        column_name="Domain",
    )


class BlacklistEngine(ActionOutput):
    """Individual blacklist engine result"""

    name: str | None = OutputField(
        example_values=["Threat Sourcing"],
        column_name="Engine",
    )
    detected: bool | None = OutputField(
        example_values=[True, False],
        column_name="Detected",
    )
    confidence: str | None = OutputField(
        example_values=["high", "medium", "low"],
        column_name="Confidence",
    )
    reference: str | None = OutputField(
        cef_types=["url"],
        example_values=["https://www.threatsourcing.com/"],
        column_name="Reference",
    )
    elapsed_ms: str | None = OutputField(
        example_values=["0.00", "0.01"],
    )


class DomainReputationDetails(ActionOutput):
    """Domain reputation check details and results"""

    # Basic Domain Info
    host: str | None = OutputField(
        cef_types=["domain", "host name"],
        example_values=["google.com", "example.com"],
    )

    # Blacklist Scan Results
    detections: int | None = OutputField(
        example_values=[0, 5, 12],
    )
    engines_count: int | None = OutputField(
        example_values=[90, 95, 100],
    )
    detection_rate: str | None = OutputField(
        example_values=["0%", "5%", "12%"],
    )
    scan_time_ms: str | None = OutputField(
        example_values=["0.01", "0.27", "1.23"],
    )
    elapsed_ms: int | None = OutputField(
        example_values=[45, 123, 87],
    )
    engines: list[BlacklistEngine] | None = OutputField(
        example_values=[],
    )

    # Server Details
    server_ip: str | None = OutputField(
        cef_types=["ip"],
        example_values=["192.178.219.139"],
    )
    reverse_dns: str | None = OutputField(
        cef_types=["host name"],
        example_values=["ux-in-f139.1e100.net"],
    )
    continent_code: str | None = OutputField(
        example_values=["NA", "EU", "AS"],
    )
    continent_name: str | None = OutputField(
        example_values=["North America", "Europe"],
    )
    country_code: str | None = OutputField(
        example_values=["US", "NL", "DE"],
    )
    country_name: str | None = OutputField(
        example_values=["United States", "Netherlands"],
    )
    region_name: str | None = OutputField(
        example_values=["California", "Noord-Holland"],
    )
    city_name: str | None = OutputField(
        example_values=["Mountain View", "Amsterdam"],
    )
    latitude: float | None = OutputField(
        example_values=[37.38605, 52.378502],
    )
    longitude: float | None = OutputField(
        example_values=[-122.08385, 4.89998],
    )
    isp: str | None = OutputField(
        example_values=["Google LLC", "Cloudflare"],
    )
    asn: str | None = OutputField(
        example_values=["AS15169", "AS13335"],
    )

    # Domain Category
    is_free_hosting: bool | None = OutputField(
        example_values=[True, False],
    )
    is_anonymizer: bool | None = OutputField(
        example_values=[True, False],
    )
    is_url_shortener: bool | None = OutputField(
        example_values=[True, False],
    )
    is_free_dynamic_dns: bool | None = OutputField(
        example_values=[True, False],
    )
    is_code_sandbox: bool | None = OutputField(
        example_values=[True, False],
    )
    is_form_builder: bool | None = OutputField(
        example_values=[True, False],
    )
    is_free_file_sharing: bool | None = OutputField(
        example_values=[True, False],
    )
    is_pastebin: bool | None = OutputField(
        example_values=[True, False],
    )

    # Security Checks
    is_most_abused_tld: bool | None = OutputField(
        example_values=[True, False],
    )
    is_suspicious_homoglyph: bool | None = OutputField(
        example_values=[True, False],
    )
    is_possible_typosquatting: bool | None = OutputField(
        example_values=[True, False],
    )
    website_popularity: str | None = OutputField(
        example_values=["high", "medium", "low"],
    )
    is_risky_category: bool | None = OutputField(
        example_values=[True, False],
    )

    # Domain Parts
    root_domain: str | None = OutputField(
        cef_types=["domain"],
        example_values=["google.com", "example.org"],
    )
    subdomain: str | None = OutputField(
        example_values=["www", "mail", ""],
    )
    tld: str | None = OutputField(
        example_values=["com", "org", "net"],
    )

    # Risk Score
    risk_score: int | None = OutputField(
        example_values=[0, 50, 100],
    )


class DomainReputationSummary(ActionOutput):
    """Summary information for domain reputation check"""

    detections: int | None = OutputField(example_values=[0, 5, 12])
    engines_count: int | None = OutputField(example_values=[90, 95, 100])
    detection_rate: str | None = OutputField(example_values=["0%", "5%", "12%"])

    def get_message(self) -> str:
        """Generate formatted summary message"""
        if self.detections is not None and self.engines_count is not None:
            return f"Detections: {self.detections}, Engines count: {self.engines_count}"
        elif self.detection_rate is not None:
            return f"Detection rate: {self.detection_rate}"
        else:
            return "Domain reputation check completed (no detection data)"


def domain_reputation(
    param: DomainReputationParams,
    soar: SOARClient[DomainReputationSummary],
    asset: Asset,
) -> DomainReputationDetails:
    """Check domain reputation against multiple blacklist engines."""
    logger.info(MSG_QUERYING_DOMAIN_REP.format(param.domain))

    params = {"host": param.domain}
    data = _make_api_request(ENDPOINT_DOMAIN_REPUTATION, asset, params)

    blacklists = data.get(KEY_BLACKLISTS)
    if not blacklists:
        raise Exception(ERROR_NO_BLACKLIST_DATA)

    engines_list = []
    engines_data = blacklists.get(KEY_ENGINES, {})
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

    server_details = data.get("server_details", {})
    category = data.get("category", {})
    security_checks = data.get("security_checks", {})
    domain_parts = data.get("domain_parts", {})
    risk_score = data.get("risk_score", {})

    result = DomainReputationDetails(
        host=data.get("host", param.domain),
        detections=blacklists.get("detections"),
        engines_count=blacklists.get("engines_count"),
        detection_rate=blacklists.get("detection_rate"),
        scan_time_ms=str(blacklists.get("scan_time_ms", "0.00")),
        elapsed_ms=data.get("elapsed_ms"),
        engines=engines_list,
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
        is_free_hosting=category.get("is_free_hosting"),
        is_anonymizer=category.get("is_anonymizer"),
        is_url_shortener=category.get("is_url_shortener"),
        is_free_dynamic_dns=category.get("is_free_dynamic_dns"),
        is_code_sandbox=category.get("is_code_sandbox"),
        is_form_builder=category.get("is_form_builder"),
        is_free_file_sharing=category.get("is_free_file_sharing"),
        is_pastebin=category.get("is_pastebin"),
        is_most_abused_tld=security_checks.get("is_most_abused_tld"),
        is_suspicious_homoglyph=security_checks.get("is_suspicious_homoglyph"),
        is_possible_typosquatting=security_checks.get("is_possible_typosquatting"),
        website_popularity=security_checks.get("website_popularity"),
        is_risky_category=security_checks.get("is_risky_category"),
        root_domain=domain_parts.get("root_domain"),
        subdomain=domain_parts.get("subdomain"),
        tld=domain_parts.get("tld"),
        risk_score=risk_score.get("result"),
    )

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
