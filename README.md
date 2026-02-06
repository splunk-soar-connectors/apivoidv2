# APIvoid v2

Publisher: Splunk Inc. <br>
Connector Version: 1.0.2 <br>
Product Vendor: APIVoid <br>
Product Name: APIVoid <br>
Minimum Product Version: 7.0.0

APIVoid v2 connector for Splunk SOAR using the SDK

### Configuration variables

This table lists the configuration variables required to operate APIvoid v2. These variables are specified when configuring a APIVoid asset in Splunk SOAR.

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
action_result.data.\*.host | string | `domain` `host name` | google.com |
action_result.data.\*.elapsed_ms | numeric | | 45 123 87 |
action_result.data.\*.expired | boolean | | True False |
action_result.data.\*.valid | boolean | | True False |
action_result.data.\*.valid_peer | boolean | | True False |
action_result.data.\*.name_match | boolean | | True False |
action_result.data.\*.blacklisted | boolean | | True False |
action_result.data.\*.revoked | boolean | | True False |
action_result.data.\*.certificate_type | string | | Domain Validation Extended Validation Organization Validation |
action_result.data.\*.fingerprint_sha1 | string | `sha1` `hash` | f81e3171fa085bc04c83b6644b9f229f0cba8e57 |
action_result.data.\*.fingerprint_sha256 | string | `sha256` `hash` | faf941ad6b7339463bcea590e77e39f7930a168eb6d130d79c3be12c5de83894 |
action_result.data.\*.deprecated_issuer | boolean | | True False |
action_result.data.\*.certificate_hash | string | `hash` | d5b02a29 |
action_result.data.\*.certificate_version | string | | 2 3 |
action_result.data.\*.subject_name | string | | /C=US/ST=California/L=Mountain View/O=Google LLC/CN=\*.google.com |
action_result.data.\*.subject_common_name | string | `domain` | \*.google.com paypal.com |
action_result.data.\*.subject_alternative_names | string | | DNS:\*.google.com, DNS:google.com, DNS:\*.youtube.com |
action_result.data.\*.subject_organization | string | | Google LLC PayPal, Inc. |
action_result.data.\*.subject_organization_unit | string | | IT Department |
action_result.data.\*.subject_category | string | | Private Organization Business Entity |
action_result.data.\*.subject_country | string | | US GB |
action_result.data.\*.subject_state | string | | California Delaware |
action_result.data.\*.subject_location | string | | Mountain View San Jose |
action_result.data.\*.subject_postal_code | string | | 94043 |
action_result.data.\*.subject_street | string | | 1600 Amphitheatre Parkway |
action_result.data.\*.subject_serial_number | string | | 3014267 |
action_result.data.\*.subject_inc_country | string | | US DE |
action_result.data.\*.subject_inc_state | string | | Delaware Nevada |
action_result.data.\*.issuer_common_name | string | | Google Internet Authority G3 DigiCert EV RSA CA G2 |
action_result.data.\*.issuer_organization | string | | Google Trust Services DigiCert Inc |
action_result.data.\*.issuer_organization_unit | string | | Organization Unit |
action_result.data.\*.issuer_country | string | | US GB |
action_result.data.\*.issuer_state | string | | California |
action_result.data.\*.issuer_location | string | | Mountain View |
action_result.data.\*.public_key_algorithm | string | | RSA ECDSA |
action_result.data.\*.public_key_size | numeric | | 2048 4096 256 |
action_result.data.\*.signature_serial | string | | 154395212770671185670675998830856977631 |
action_result.data.\*.signature_serial_hex | string | `md5` `hash` | 74276FB4EDD2D5219515679EAE273CDF |
action_result.data.\*.signature_type | string | | RSA-SHA256 SHA256-RSA SHA384-RSA |
action_result.data.\*.valid_from | string | | Fri, 01 Mar 2019 09:43:57 GMT Mon, 26 Aug 2024 00:00:00 UTC |
action_result.data.\*.valid_to | string | | Fri, 24 May 2019 09:25:00 GMT Mon, 25 Aug 2025 23:59:59 UTC |
action_result.data.\*.valid_from_timestamp | numeric | | 1551433437 1724630400 |
action_result.data.\*.valid_to_timestamp | numeric | | 1558689900 1756166399 |
action_result.data.\*.days_left | numeric | | 60 30 90 269 |
action_result.data.\*.extensions_authority_info_access | string | | CA Issuers - URI:http://pki.goog/gsr2/GTSGIAG3.crt OCSP - URI:http://ocsp.pki.goog/GTSGIAG3 |
action_result.data.\*.extensions_authority_key_identifier | string | | keyid:77:C2:B8:50:9A:67:76:76:B1:2D:C2:86:D0:83:A0:7E:A6:7E:BA:4B |
action_result.data.\*.extensions_subject_key_identifier | string | | AD:04:58:61:3A:F6:D7:C7:56:6B:20:0B:58:09:79:11:22:F7:69:B6 |
action_result.data.\*.extensions_basic_constraints | string | | CA:FALSE CA:TRUE |
action_result.data.\*.extensions_certificate_policies | string | | Policy: 1.3.6.1.4.1.11129.2.5.3 Policy: 2.23.140.1.2.2 |
action_result.data.\*.extensions_crl_distribution_points | string | | Full Name: URI:http://crl.pki.goog/GTSGIAG3.crl |
action_result.data.\*.extensions_key_usage | string | | Digital Signature Digital Signature, Key Encipherment |
action_result.data.\*.extensions_extended_key_usage | string | | TLS Web Server Authentication Server Authentication, Client Authentication |
action_result.data.\*.certificate_authority | boolean | | True False |
action_result.data.\*.authority_key_id | string | | 301680146a4e50bf98689d5b7b2075d45901794866923206 |
action_result.data.\*.subject_key_id | string | | 04148d939fbf9c7cf8ba64066baa73bb814351b7dc41 |
action_result.data.\*.key_usages | string | | Digital Signature, Key Encipherment |
action_result.data.\*.extended_key_usages | string | | Server Authentication, Client Authentication |
action_result.data.\*.crl_endpoints | string | `url` | http://crl3.digicert.com/DigiCertEVRSACAG2.crl, http://crl4.digicert.com/DigiCertEVRSACAG2.crl |
action_result.data.\*.authority_info | string | | OCSP: http://o.pki.goog/wr2, CA Issuers: http://i.pki.goog/wr2.crt |
action_result.summary.certificate_found | boolean | | True False |
action_result.summary.domain | string | | google.com example.com |
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
action_result.data.\*.ip | string | `ip` | 8.8.8.8 1.1.1.1 |
action_result.data.\*.version | string | | IPv4 IPv6 |
action_result.data.\*.detections | numeric | | 0 5 12 |
action_result.data.\*.engines_count | numeric | | 90 95 100 |
action_result.data.\*.detection_rate | string | | 0% 5% 12% |
action_result.data.\*.scan_time_ms | string | | 0.01 0.27 1.23 |
action_result.data.\*.elapsed_ms | numeric | | 45 123 87 |
action_result.data.\*.engines.\*.name | string | | Roquesor BL |
action_result.data.\*.engines.\*.detected | boolean | | True False |
action_result.data.\*.engines.\*.reference | string | `url` | https://es.roquesor.com/en/ |
action_result.data.\*.engines.\*.elapsed_ms | string | | 0.00 0.01 |
action_result.data.\*.reverse_dns | string | `host name` | dojo.census.shodan.io |
action_result.data.\*.continent_code | string | | EU NA AS |
action_result.data.\*.continent_name | string | | Europe North America |
action_result.data.\*.country_code | string | | US NL DE |
action_result.data.\*.country_name | string | | United States Netherlands |
action_result.data.\*.region_name | string | | California Noord-Holland |
action_result.data.\*.city_name | string | | Amsterdam Mountain View |
action_result.data.\*.latitude | numeric | | 52.378502 37.38605 |
action_result.data.\*.longitude | numeric | | 4.89998 -122.08385 |
action_result.data.\*.isp | string | | Google LLC FiberXpress BV |
action_result.data.\*.is_bogon | boolean | | True False |
action_result.data.\*.is_spamhaus_drop | boolean | | True False |
action_result.data.\*.is_fake_bot | boolean | | True False |
action_result.data.\*.is_google_bot | boolean | | True False |
action_result.data.\*.is_search_engine_bot | boolean | | True False |
action_result.data.\*.is_public_dns | boolean | | True False |
action_result.data.\*.cloud_provider | string | | AWS Google Cloud Azure |
action_result.data.\*.aws_service | string | | EC2 Lambda |
action_result.data.\*.is_google_service | boolean | | True False |
action_result.data.\*.is_satellite | boolean | | True False |
action_result.data.\*.asn | string | | AS15169 AS202425 |
action_result.data.\*.asname | string | | INT-NETWORK GOOGLE |
action_result.data.\*.asn_route | string | | 80.82.77.0/24 |
action_result.data.\*.asn_org | string | | Google LLC IP Volume inc |
action_result.data.\*.asn_country_code | string | | US SC |
action_result.data.\*.abuse_email | string | `email` | abuse@google.com |
action_result.data.\*.asn_domain | string | `domain` | google.com ipvolume.net |
action_result.data.\*.asn_type | string | | hosting isp business |
action_result.data.\*.is_proxy | boolean | | True False |
action_result.data.\*.is_webproxy | boolean | | True False |
action_result.data.\*.is_residential_proxy | boolean | | True False |
action_result.data.\*.is_vpn | boolean | | True False |
action_result.data.\*.is_hosting | boolean | | True False |
action_result.data.\*.is_relay | boolean | | True False |
action_result.data.\*.is_tor | boolean | | True False |
action_result.data.\*.risk_score | numeric | | 0 50 100 |
action_result.summary.detections | numeric | | 0 5 12 |
action_result.summary.engines_count | numeric | | 90 95 100 |
action_result.summary.detection_rate | string | | 0% 5% 12% |
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
action_result.data.\*.host | string | `domain` `host name` | google.com example.com |
action_result.data.\*.detections | numeric | | 0 5 12 |
action_result.data.\*.engines_count | numeric | | 90 95 100 |
action_result.data.\*.detection_rate | string | | 0% 5% 12% |
action_result.data.\*.scan_time_ms | string | | 0.01 0.27 1.23 |
action_result.data.\*.elapsed_ms | numeric | | 45 123 87 |
action_result.data.\*.engines.\*.name | string | | Threat Sourcing |
action_result.data.\*.engines.\*.detected | boolean | | True False |
action_result.data.\*.engines.\*.confidence | string | | high medium low |
action_result.data.\*.engines.\*.reference | string | `url` | https://www.threatsourcing.com/ |
action_result.data.\*.engines.\*.elapsed_ms | string | | 0.00 0.01 |
action_result.data.\*.server_ip | string | `ip` | 192.178.219.139 |
action_result.data.\*.reverse_dns | string | `host name` | ux-in-f139.1e100.net |
action_result.data.\*.continent_code | string | | NA EU AS |
action_result.data.\*.continent_name | string | | North America Europe |
action_result.data.\*.country_code | string | | US NL DE |
action_result.data.\*.country_name | string | | United States Netherlands |
action_result.data.\*.region_name | string | | California Noord-Holland |
action_result.data.\*.city_name | string | | Mountain View Amsterdam |
action_result.data.\*.latitude | numeric | | 37.38605 52.378502 |
action_result.data.\*.longitude | numeric | | -122.08385 4.89998 |
action_result.data.\*.isp | string | | Google LLC Cloudflare |
action_result.data.\*.asn | string | | AS15169 AS13335 |
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
action_result.data.\*.website_popularity | string | | high medium low |
action_result.data.\*.is_risky_category | boolean | | True False |
action_result.data.\*.root_domain | string | `domain` | google.com example.org |
action_result.data.\*.subdomain | string | | www mail |
action_result.data.\*.tld | string | | com org net |
action_result.data.\*.risk_score | numeric | | 0 50 100 |
action_result.summary.detections | numeric | | 0 5 12 |
action_result.summary.engines_count | numeric | | 90 95 100 |
action_result.summary.detection_rate | string | | 0% 5% 12% |
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
