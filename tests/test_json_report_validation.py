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
import unittest

from joesandboxv2_consts import JOE_JSON_ANALYSIS, JOE_JSON_RESPONSE
from joesandboxv2_report import get_nonempty_report_analysis


class JsonReportValidationTestCase(unittest.TestCase):
    def test_missing_report_response_fails(self):
        self.assertIsNone(get_nonempty_report_analysis({}))

    def test_empty_analysis_fails(self):
        response = {JOE_JSON_RESPONSE: {JOE_JSON_ANALYSIS: {}}}
        self.assertIsNone(get_nonempty_report_analysis(response))

    def test_nonempty_but_unusable_analysis_fails(self):
        response = {JOE_JSON_RESPONSE: {JOE_JSON_ANALYSIS: {"generalinfo": {}}}}
        self.assertIsNone(get_nonempty_report_analysis(response))

    def test_nonempty_analysis_passes(self):
        analysis = {"generalinfo": {"target": "sample"}}
        response = {JOE_JSON_RESPONSE: {JOE_JSON_ANALYSIS: analysis}}
        self.assertIs(get_nonempty_report_analysis(response), analysis)


if __name__ == "__main__":
    unittest.main()
