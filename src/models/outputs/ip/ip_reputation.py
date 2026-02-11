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
"""IP reputation models for ip_reputation action"""

from soar_sdk.action_results import ActionOutput, OutputField


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
