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
"""REST client for APIVoid v2 API call"""

import requests
from soar_sdk.logging import getLogger

from .apivoid_consts import (
    CONTENT_TYPE_JSON,
    DEFAULT_TIMEOUT,
    ERROR_API_ERROR,
    ERROR_CONNECTION,
    ERROR_HTTP,
    ERROR_INVALID_JSON,
    ERROR_REQUEST,
    ERROR_TIMEOUT,
    HEADER_API_KEY,
    HEADER_CONTENT_TYPE,
    KEY_ERROR,
    MSG_MAKING_API_REQUEST,
)
from .asset import Asset

logger = getLogger()


def _make_api_request(endpoint: str, asset: Asset, params: dict) -> dict:
    """
    REST API call to APIVoid v2.

    :param endpoint: API endpoint (e.g., 'v2/ssl-info')
    :param asset: Asset instance (server_url, api_key)
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
