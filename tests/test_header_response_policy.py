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
import re
import unittest
from pathlib import Path


CONNECTOR = Path(__file__).resolve().parents[1] / "hackertarget_connector.py"


class HeaderResponsePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = CONNECTOR.read_text()
        tree = ast.parse(source)
        helpers = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in {"_contains_header_service_error", "_parse_http_header_response"}
        ]
        namespace = {"re": re}
        exec(compile(ast.fix_missing_locations(ast.Module(body=helpers, type_ignores=[])), str(CONNECTOR), "exec"), namespace)
        cls.contains_error = staticmethod(namespace["_contains_header_service_error"])
        cls.parse_headers = staticmethod(namespace["_parse_http_header_response"])

    def test_header_action_never_persists_raw_response_in_status(self):
        source = CONNECTOR.read_text()
        tree = ast.parse(source)
        handler = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_get_http_headers")
        handler_source = ast.get_source_segment(source, handler)

        self.assertNotIn("set_status(phantom.APP_SUCCESS, response)", handler_source)
        self.assertNotIn("set_status(phantom.APP_ERROR, response)", handler_source)
        self.assertIn('set_status(phantom.APP_ERROR, "Header service returned an error")', handler_source)
        self.assertIn('set_status(phantom.APP_ERROR, "Header service request failed")', handler_source)
        self.assertIn("redact_response=True", handler_source)

        helper = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_make_rest_call")
        for call in (node for node in ast.walk(helper) if isinstance(node, ast.Call)):
            if isinstance(call.func, ast.Attribute) and call.func.attr == "set_status":
                self.assertNotIn("r.text", ast.get_source_segment(source, call))

    def test_cookie_headers_are_removed_with_or_without_whitespace(self):
        response = "\n".join(
            (
                "HTTP/1.1 200 OK",
                "Set-Cookie:session=secret Path=/ Secure",
                "cOoKiE : session=second",
                "SET-COOKIE2:\tlegacy=third",
                "Content-Type: text/plain",
            )
        )

        self.assertEqual(
            self.parse_headers(response),
            [{"http_version": "1.1", "response_code": "200", "Content-Type": "text/plain"}],
        )

    def test_only_http_status_lines_populate_status_fields(self):
        response = "HTTP/1.1 200 OK\nMalformed secret-bearing text with spaces\nX-Test:value"

        self.assertEqual(
            self.parse_headers(response),
            [{"http_version": "1.1", "response_code": "200", "X-Test": "value"}],
        )

    def test_embedded_http_text_in_cookie_content_cannot_start_a_response(self):
        cases = (
            (
                "HTTP/1.1 200 OK\nSet-Cookie: sid=prefixHTTP/leaked 200 OK\nX-Test:value",
                {"http_version": "1.1", "response_code": "200", "X-Test": "value"},
            ),
            (
                "HTTP/1.1 200 OK\nSet-Cookie: sid=prefix\n HTTP/leaked 200 OK\n X-Leaked: secret",
                {"http_version": "1.1", "response_code": "200"},
            ),
            (
                "HTTP/1.1 200 OK\nX-Test: prefixHTTP/leaked 200 OK",
                {"http_version": "1.1", "response_code": "200", "X-Test": "prefixHTTP/leaked 200 OK"},
            ),
        )
        for response, expected in cases:
            with self.subTest(response=response):
                self.assertEqual(self.parse_headers(response), [expected])

    def test_multiple_real_response_blocks_support_lf_and_crlf(self):
        for separator in ("\n", "\r\n"):
            response = separator.join(
                (
                    "HTTP/1.1 301 Moved",
                    "Location: https://example.invalid",
                    "Set-Cookie: first=secret",
                    "HTTP/2 200 OK",
                    "Content-Type: text/plain",
                )
            )
            with self.subTest(separator=repr(separator)):
                self.assertEqual(
                    self.parse_headers(response),
                    [
                        {"http_version": "1.1", "response_code": "301", "Location": "https://example.invalid"},
                        {"http_version": "2", "response_code": "200", "Content-Type": "text/plain"},
                    ],
                )

    def test_service_error_detection_is_case_and_spacing_insensitive(self):
        for response in ("error: denied", "ERROR : denied", "HTTP/1.1 200 OK\nError: denied"):
            with self.subTest(response=response):
                self.assertTrue(self.contains_error(response))


if __name__ == "__main__":
    unittest.main()
