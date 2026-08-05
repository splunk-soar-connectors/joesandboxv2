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
from joesandboxv2_consts import (
    JOE_JSON_ANALYSIS,
    JOE_JSON_BEHAVIOR,
    JOE_JSON_DOMAIN_INFO,
    JOE_JSON_DROPPED_INFO,
    JOE_JSON_FILE_INFO,
    JOE_JSON_GENERAL_INFO,
    JOE_JSON_IP_INFO,
    JOE_JSON_RESPONSE,
    JOE_JSON_SIGNATURED_DETECTIONS,
)


USABLE_ANALYSIS_SECTIONS = (
    JOE_JSON_GENERAL_INFO,
    JOE_JSON_FILE_INFO,
    JOE_JSON_DOMAIN_INFO,
    JOE_JSON_IP_INFO,
    JOE_JSON_SIGNATURED_DETECTIONS,
    JOE_JSON_DROPPED_INFO,
    JOE_JSON_BEHAVIOR,
)


def get_nonempty_report_analysis(response_data):
    """Return the analysis object only when the report response is usable."""
    if not isinstance(response_data, dict):
        return None

    report = response_data.get(JOE_JSON_RESPONSE)
    if not isinstance(report, dict):
        return None

    analysis = report.get(JOE_JSON_ANALYSIS)
    if not isinstance(analysis, dict) or not any(analysis.get(section) for section in USABLE_ANALYSIS_SECTIONS):
        return None

    return analysis
