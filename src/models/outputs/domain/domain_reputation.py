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
"""Domain reputation models for domain_reputation action"""

from soar_sdk.action_results import ActionOutput, OutputField


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
