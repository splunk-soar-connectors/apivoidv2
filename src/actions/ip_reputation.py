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


class IpReputationParams(Params):
    """Parameters for IP reputation action"""

    ip: str = Param(
        description="IP address to check reputation",
        required=True,
        primary=True,
        cef_types=["ip"],
        column_name="IP Address",
    )


class IpBlacklistEngine(ActionOutput):
    """Individual blacklist engine result for IP"""

    name: str | None = OutputField(
        example_values=["Roquesor BL"],
        column_name="Engine",
    )
    detected: bool | None = OutputField(
        example_values=[True, False],
        column_name="Detected",
    )
    reference: str | None = OutputField(
        cef_types=["url"],
        example_values=["https://es.roquesor.com/en/"],
        column_name="Reference",
    )
    elapsed_ms: str | None = OutputField(
        example_values=["0.00", "0.01"],
    )


class IpReputationDetails(ActionOutput):
    """IP reputation check details and results"""

    # Basic IP Info
    ip: str | None = OutputField(
        cef_types=["ip"],
        example_values=["8.8.8.8", "1.1.1.1"],
    )
    version: str | None = OutputField(
        example_values=["IPv4", "IPv6"],
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
    engines: list[IpBlacklistEngine] | None = OutputField(
        example_values=[],
    )

    # Geolocation Information
    reverse_dns: str | None = OutputField(
        cef_types=["host name"],
        example_values=["dojo.census.shodan.io"],
    )
    continent_code: str | None = OutputField(
        example_values=["EU", "NA", "AS"],
    )
    continent_name: str | None = OutputField(
        example_values=["Europe", "North America"],
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
        example_values=["Amsterdam", "Mountain View"],
    )
    latitude: float | None = OutputField(
        example_values=[52.378502, 37.38605],
    )
    longitude: float | None = OutputField(
        example_values=[4.89998, -122.08385],
    )
    isp: str | None = OutputField(
        example_values=["Google LLC", "FiberXpress BV"],
    )

    # Bot & Service Detection
    is_bogon: bool | None = OutputField(
        example_values=[True, False],
    )
    is_spamhaus_drop: bool | None = OutputField(
        example_values=[True, False],
    )
    is_fake_bot: bool | None = OutputField(
        example_values=[True, False],
    )
    is_google_bot: bool | None = OutputField(
        example_values=[True, False],
    )
    is_search_engine_bot: bool | None = OutputField(
        example_values=[True, False],
    )
    is_public_dns: bool | None = OutputField(
        example_values=[True, False],
    )
    cloud_provider: str | None = OutputField(
        example_values=["AWS", "Google Cloud", "Azure"],
    )
    aws_service: str | None = OutputField(
        example_values=["EC2", "Lambda", ""],
    )
    is_google_service: bool | None = OutputField(
        example_values=[True, False],
    )
    is_satellite: bool | None = OutputField(
        example_values=[True, False],
    )

    # ASN Details
    asn: str | None = OutputField(
        example_values=["AS15169", "AS202425"],
    )
    asname: str | None = OutputField(
        example_values=["INT-NETWORK", "GOOGLE"],
    )
    asn_route: str | None = OutputField(
        example_values=["80.82.77.0/24"],
    )
    asn_org: str | None = OutputField(
        example_values=["Google LLC", "IP Volume inc"],
    )
    asn_country_code: str | None = OutputField(
        example_values=["US", "SC"],
    )
    abuse_email: str | None = OutputField(
        cef_types=["email"],
        example_values=["abuse@google.com"],
    )
    asn_domain: str | None = OutputField(
        cef_types=["domain"],
        example_values=["google.com", "ipvolume.net"],
    )
    asn_type: str | None = OutputField(
        example_values=["hosting", "isp", "business"],
    )

    # Anonymity Detection
    is_proxy: bool | None = OutputField(
        example_values=[True, False],
    )
    is_webproxy: bool | None = OutputField(
        example_values=[True, False],
    )
    is_residential_proxy: bool | None = OutputField(
        example_values=[True, False],
    )
    is_vpn: bool | None = OutputField(
        example_values=[True, False],
    )
    is_hosting: bool | None = OutputField(
        example_values=[True, False],
    )
    is_relay: bool | None = OutputField(
        example_values=[True, False],
    )
    is_tor: bool | None = OutputField(
        example_values=[True, False],
    )

    # Risk Score
    risk_score: int | None = OutputField(
        example_values=[0, 50, 100],
    )


class IpReputationSummary(ActionOutput):
    """Summary information for IP reputation check"""

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
            return "IP reputation check completed (no detection data)"


def ip_reputation(
    param: IpReputationParams,
    soar: SOARClient[IpReputationSummary],
    asset: Asset,
) -> IpReputationDetails:
    """Check IP address reputation against multiple blacklist engines."""
    logger.info(MSG_QUERYING_IP_REP.format(param.ip))

    params = {"ip": param.ip}
    data = _make_api_request(ENDPOINT_IP_REPUTATION, asset, params)

    blacklists = data.get(KEY_BLACKLISTS)
    if not blacklists:
        raise Exception(ERROR_NO_BLACKLIST_DATA)

    engines_list = []
    engines_data = blacklists.get(KEY_ENGINES, {})
    for engine_name, engine_info in engines_data.items():
        engines_list.append(
            IpBlacklistEngine(
                name=engine_info.get("name", engine_name),
                detected=engine_info.get("detected"),
                reference=engine_info.get("reference"),
                elapsed_ms=str(engine_info.get("elapsed_ms", "0.00")),
            )
        )

    information = data.get("information", {})
    asn_data = data.get("asn", {})
    anonymity = data.get("anonymity", {})
    risk_score = data.get("risk_score", {})

    result = IpReputationDetails(
        ip=data.get("ip"),
        version=data.get("version"),
        detections=blacklists.get("detections"),
        engines_count=blacklists.get("engines_count"),
        detection_rate=blacklists.get("detection_rate"),
        scan_time_ms=str(blacklists.get("scan_time_ms", "0.00")),
        elapsed_ms=data.get("elapsed_ms"),
        engines=engines_list,
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
        asn=asn_data.get("asn"),
        asname=asn_data.get("asname"),
        asn_route=asn_data.get("route"),
        asn_org=asn_data.get("org"),
        asn_country_code=asn_data.get("country_code"),
        abuse_email=asn_data.get("abuse_email"),
        asn_domain=asn_data.get("domain"),
        asn_type=asn_data.get("type"),
        is_proxy=anonymity.get("is_proxy"),
        is_webproxy=anonymity.get("is_webproxy"),
        is_residential_proxy=anonymity.get("is_residential_proxy"),
        is_vpn=anonymity.get("is_vpn"),
        is_hosting=anonymity.get("is_hosting"),
        is_relay=anonymity.get("is_relay"),
        is_tor=anonymity.get("is_tor"),
        risk_score=risk_score.get("result"),
    )

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
