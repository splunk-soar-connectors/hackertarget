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
import ast
import unittest
from pathlib import Path


CONNECTOR = Path(__file__).resolve().parents[1] / "hackertarget_connector.py"


class HeaderResponsePolicyTests(unittest.TestCase):
    def test_header_action_never_persists_raw_response_in_status(self):
        source = CONNECTOR.read_text()
        tree = ast.parse(source)
        handler = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_get_http_headers")
        handler_source = ast.get_source_segment(source, handler)

        self.assertNotIn("set_status(phantom.APP_SUCCESS, response)", handler_source)
        self.assertNotIn("set_status(phantom.APP_ERROR, response)", handler_source)
        self.assertIn('set_status(phantom.APP_ERROR, "Header service returned an error")', handler_source)
        self.assertIn('set_status(phantom.APP_ERROR, "Header service request failed")', handler_source)


if __name__ == "__main__":
    unittest.main()
