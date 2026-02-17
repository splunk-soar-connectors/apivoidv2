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
        primary=True,
        column_name="Domain",
    )


class BlacklistEngine(ActionOutput):
    """Individual blacklist engine result"""

    name: str | None = OutputField(
        column_name="Engine",
    )
    detected: bool | None = OutputField(
        column_name="Detected",
    )
    confidence: str | None = OutputField(
        column_name="Confidence",
    )
    reference: str | None = OutputField(
        column_name="Reference",
    )
    elapsed_ms: int | None = OutputField()


class DomainReputationDetails(ActionOutput):
    """Domain reputation check details and results"""

    # Basic Domain Info
    host: str | None = OutputField()

    # Blacklist Scan Results
    detections: int | None = OutputField()
    engines_count: int | None = OutputField()
    detection_rate: str | None = OutputField()
    scan_time_ms: int | None = OutputField()
    elapsed_ms: int | None = OutputField()
    engines: list[BlacklistEngine] | None = OutputField()

    # Server Details
    server_ip: str | None = OutputField()
    reverse_dns: str | None = OutputField()
    continent_code: str | None = OutputField()
    continent_name: str | None = OutputField()
    country_code: str | None = OutputField()
    country_name: str | None = OutputField()
    region_name: str | None = OutputField()
    city_name: str | None = OutputField()
    latitude: float | None = OutputField()
    longitude: float | None = OutputField()
    isp: str | None = OutputField()
    asn: str | None = OutputField()

    # Domain Category
    is_free_hosting: bool | None = OutputField()
    is_anonymizer: bool | None = OutputField()
    is_url_shortener: bool | None = OutputField()
    is_free_dynamic_dns: bool | None = OutputField()
    is_code_sandbox: bool | None = OutputField()
    is_form_builder: bool | None = OutputField()
    is_free_file_sharing: bool | None = OutputField()
    is_pastebin: bool | None = OutputField()

    # Security Checks
    is_most_abused_tld: bool | None = OutputField()
    is_suspicious_homoglyph: bool | None = OutputField()
    is_possible_typosquatting: bool | None = OutputField()
    website_popularity: str | None = OutputField()
    is_risky_category: bool | None = OutputField()

    # Domain Parts
    root_domain: str | None = OutputField()
    subdomain: str | None = OutputField()
    tld: str | None = OutputField()

    # Risk Score
    risk_score: int | None = OutputField()


class DomainReputationSummary(ActionOutput):
    """Summary information for domain reputation check"""

    detections: int | None = OutputField()
    engines_count: int | None = OutputField()
    detection_rate: str | None = OutputField()

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
                elapsed_ms=int(engine_info.get("elapsed_ms")),
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
        scan_time_ms=int(blacklists.get("scan_time_ms")),
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
