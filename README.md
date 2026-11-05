# APIvoid v2

Publisher: Splunk <br>
Connector Version: 1.0.2 <br>
Product Vendor: APIVoid <br>
Product Name: APIVoid v2 <br>
Minimum Product Version: 7.0.0

APIVoid v2 connector for Splunk SOAR using the SDK

### Configuration variables

This table lists the configuration variables required to operate APIvoid v2. These variables are specified when configuring a APIVoid v2 asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**server_url** | required | string | API Server URL (e.g., https://api.apivoid.com) |
**api_key** | required | password | API Key for authentication |

### Supported Actions

[test connectivity](#action-test-connectivity) - Test connectivity to APIVoid v2 API <br>
[get cert info](#action-get-cert-info) - Query certificate information for a domain <br>
[ip reputation](#action-ip-reputation) - Check IP address reputation against blacklists <br>
[domain reputation](#action-domain-reputation) - Check domain reputation against blacklists

## action: 'test connectivity'

Test connectivity to APIVoid v2 API

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get cert info'

Query certificate information for a domain

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to query (e.g., google.com) | string | `domain` `url` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.domain | string | `domain` `url` | |
action_result.data.\*.certificate_found | boolean | `certificate` | True False |
action_result.data.\*.host | string | `domain` `host name` | |
action_result.data.\*.elapsed_ms | numeric | | |
action_result.data.\*.expired | boolean | | True False |
action_result.data.\*.valid | boolean | | True False |
action_result.data.\*.valid_peer | boolean | | True False |
action_result.data.\*.name_match | boolean | | True False |
action_result.data.\*.blacklisted | boolean | | True False |
action_result.data.\*.revoked | boolean | | True False |
action_result.data.\*.certificate_type | string | | |
action_result.data.\*.fingerprint_sha1 | string | | |
action_result.data.\*.fingerprint_sha256 | string | | |
action_result.data.\*.deprecated_issuer | boolean | | True False |
action_result.data.\*.certificate_hash | string | | |
action_result.data.\*.certificate_version | string | | |
action_result.data.\*.subject_name | string | | |
action_result.data.\*.subject_common_name | string | | |
action_result.data.\*.subject_alternative_names | string | | |
action_result.data.\*.subject_organization | string | | |
action_result.data.\*.subject_organization_unit | string | | |
action_result.data.\*.subject_category | string | | |
action_result.data.\*.subject_country | string | | |
action_result.data.\*.subject_state | string | | |
action_result.data.\*.subject_location | string | | |
action_result.data.\*.subject_postal_code | string | | |
action_result.data.\*.subject_street | string | | |
action_result.data.\*.subject_serial_number | string | | |
action_result.data.\*.subject_inc_country | string | | |
action_result.data.\*.subject_inc_state | string | | |
action_result.data.\*.issuer_common_name | string | | |
action_result.data.\*.issuer_organization | string | | |
action_result.data.\*.issuer_organization_unit | string | | |
action_result.data.\*.issuer_country | string | | |
action_result.data.\*.issuer_state | string | | |
action_result.data.\*.issuer_location | string | | |
action_result.data.\*.public_key_algorithm | string | | |
action_result.data.\*.public_key_size | numeric | | |
action_result.data.\*.signature_serial | string | | |
action_result.data.\*.signature_serial_hex | string | | |
action_result.data.\*.signature_type | string | | |
action_result.data.\*.valid_from | string | | |
action_result.data.\*.valid_to | string | | |
action_result.data.\*.valid_from_timestamp | numeric | | |
action_result.data.\*.valid_to_timestamp | numeric | | |
action_result.data.\*.days_left | numeric | | |
action_result.data.\*.extensions_authority_info_access | string | | |
action_result.data.\*.extensions_authority_key_identifier | string | | |
action_result.data.\*.extensions_subject_key_identifier | string | | |
action_result.data.\*.extensions_basic_constraints | string | | |
action_result.data.\*.extensions_certificate_policies | string | | |
action_result.data.\*.extensions_crl_distribution_points | string | | |
action_result.data.\*.extensions_key_usage | string | | |
action_result.data.\*.extensions_extended_key_usage | string | | |
action_result.data.\*.certificate_authority | boolean | | True False |
action_result.data.\*.authority_key_id | string | | |
action_result.data.\*.subject_key_id | string | | |
action_result.data.\*.key_usages | string | | |
action_result.data.\*.extended_key_usages | string | | |
action_result.data.\*.crl_endpoints | string | | |
action_result.data.\*.authority_info | string | | |
action_result.summary.certificate_found | boolean | | True False |
action_result.summary.domain | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'ip reputation'

Check IP address reputation against blacklists

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** | required | IP address to check reputation | string | `ip` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip | string | `ip` | |
action_result.data.\*.ip | string | `ip` | |
action_result.data.\*.version | string | | |
action_result.data.\*.detections | numeric | | |
action_result.data.\*.engines_count | numeric | | |
action_result.data.\*.detection_rate | string | | |
action_result.data.\*.scan_time_ms | numeric | | |
action_result.data.\*.elapsed_ms | numeric | | |
action_result.data.\*.engines.\*.name | string | | |
action_result.data.\*.engines.\*.detected | boolean | | True False |
action_result.data.\*.engines.\*.reference | string | `url` | |
action_result.data.\*.engines.\*.elapsed_ms | numeric | | |
action_result.data.\*.reverse_dns | string | `host name` | |
action_result.data.\*.continent_code | string | | |
action_result.data.\*.continent_name | string | | |
action_result.data.\*.country_code | string | | |
action_result.data.\*.country_name | string | | |
action_result.data.\*.region_name | string | | |
action_result.data.\*.city_name | string | | |
action_result.data.\*.latitude | numeric | | |
action_result.data.\*.longitude | numeric | | |
action_result.data.\*.isp | string | | |
action_result.data.\*.is_bogon | boolean | | True False |
action_result.data.\*.is_spamhaus_drop | boolean | | True False |
action_result.data.\*.is_fake_bot | boolean | | True False |
action_result.data.\*.is_google_bot | boolean | | True False |
action_result.data.\*.is_search_engine_bot | boolean | | True False |
action_result.data.\*.is_public_dns | boolean | | True False |
action_result.data.\*.cloud_provider | string | | |
action_result.data.\*.aws_service | string | | |
action_result.data.\*.is_google_service | boolean | | True False |
action_result.data.\*.is_satellite | boolean | | True False |
action_result.data.\*.asn | string | | |
action_result.data.\*.asname | string | | |
action_result.data.\*.asn_route | string | | |
action_result.data.\*.asn_org | string | | |
action_result.data.\*.asn_country_code | string | | |
action_result.data.\*.abuse_email | string | `email` | |
action_result.data.\*.asn_domain | string | `domain` | |
action_result.data.\*.asn_type | string | | |
action_result.data.\*.is_proxy | boolean | | True False |
action_result.data.\*.is_webproxy | boolean | | True False |
action_result.data.\*.is_residential_proxy | boolean | | True False |
action_result.data.\*.is_vpn | boolean | | True False |
action_result.data.\*.is_hosting | boolean | | True False |
action_result.data.\*.is_relay | boolean | | True False |
action_result.data.\*.is_tor | boolean | | True False |
action_result.data.\*.risk_score | numeric | | |
action_result.summary.detections | numeric | | |
action_result.summary.engines_count | numeric | | |
action_result.summary.detection_rate | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'domain reputation'

Check domain reputation against blacklists

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | Domain to check reputation | string | `domain` `url` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.domain | string | `domain` `url` | |
action_result.data.\*.host | string | `domain` `host name` | |
action_result.data.\*.detections | numeric | | |
action_result.data.\*.engines_count | numeric | | |
action_result.data.\*.detection_rate | string | | |
action_result.data.\*.scan_time_ms | numeric | | |
action_result.data.\*.elapsed_ms | numeric | | |
action_result.data.\*.engines.\*.name | string | | |
action_result.data.\*.engines.\*.detected | boolean | | True False |
action_result.data.\*.engines.\*.confidence | string | | |
action_result.data.\*.engines.\*.reference | string | `url` | |
action_result.data.\*.engines.\*.elapsed_ms | numeric | | |
action_result.data.\*.server_ip | string | `ip` | |
action_result.data.\*.reverse_dns | string | `host name` | |
action_result.data.\*.continent_code | string | | |
action_result.data.\*.continent_name | string | | |
action_result.data.\*.country_code | string | | |
action_result.data.\*.country_name | string | | |
action_result.data.\*.region_name | string | | |
action_result.data.\*.city_name | string | | |
action_result.data.\*.latitude | numeric | | |
action_result.data.\*.longitude | numeric | | |
action_result.data.\*.isp | string | | |
action_result.data.\*.asn | string | | |
action_result.data.\*.is_free_hosting | boolean | | True False |
action_result.data.\*.is_anonymizer | boolean | | True False |
action_result.data.\*.is_url_shortener | boolean | | True False |
action_result.data.\*.is_free_dynamic_dns | boolean | | True False |
action_result.data.\*.is_code_sandbox | boolean | | True False |
action_result.data.\*.is_form_builder | boolean | | True False |
action_result.data.\*.is_free_file_sharing | boolean | | True False |
action_result.data.\*.is_pastebin | boolean | | True False |
action_result.data.\*.is_most_abused_tld | boolean | | True False |
action_result.data.\*.is_suspicious_homoglyph | boolean | | True False |
action_result.data.\*.is_possible_typosquatting | boolean | | True False |
action_result.data.\*.website_popularity | string | | |
action_result.data.\*.is_risky_category | boolean | | True False |
action_result.data.\*.root_domain | string | `domain` | |
action_result.data.\*.subdomain | string | | |
action_result.data.\*.tld | string | | |
action_result.data.\*.risk_score | numeric | | |
action_result.summary.detections | numeric | | |
action_result.summary.engines_count | numeric | | |
action_result.summary.detection_rate | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
