"""Unit tests for Windows Control Center MCP Server (Strictly Stdio Transport)."""

import asyncio
import io
import logging
import sys
import unittest
from unittest.mock import patch
from fastmcp import Client
from server import logger, mcp, parse_arguments


class TestServerConfiguration(unittest.TestCase):
    """Test suite for stdio server tool registration, metadata, and argument parsing."""

    def test_registered_tools(self):
        """Verify that all 22 anticipated tools are registered on the FastMCP instance."""
        tools = asyncio.run(mcp.list_tools())
        tool_names = {t.name for t in tools}

        expected_tools = [
            "execute_powershell",
            "execute_elevated_command",
            "get_security_status",
            "execute_cmd",
            "execute_python",
            "list_processes",
            "kill_process",
            "read_file",
            "write_file",
            "list_directory",
            "search_files",
            "get_file_info",
            "delete_file_or_dir",
            "copy_or_move",
            "get_system_info",
            "get_network_info",
            "get_environment",
            "launch_app",
            "get_clipboard",
            "set_clipboard",
            "take_screenshot",
            "show_notification",
        ]

        self.assertEqual(len(tool_names), len(expected_tools))
        for expected in expected_tools:
            self.assertIn(expected, tool_names, f"Tool '{expected}' is missing from FastMCP registry")

    def test_registered_resources_and_prompts(self):
        """Verify that system resources and prompts are properly registered."""
        # Resources
        resources = asyncio.run(mcp.list_resources())
        resource_uris = {str(r.uri) for r in resources}
        self.assertIn("system://specs", resource_uris)
        self.assertIn("system://network", resource_uris)

        # Prompts
        prompts = asyncio.run(mcp.list_prompts())
        prompt_names = {p.name for p in prompts}
        self.assertIn("system_health_check", prompt_names)

    def test_mcp_metadata_and_tool_annotations(self):
        """Verify FastMCP server version, resource mime types, and tool annotations."""
        self.assertEqual(mcp.version, "1.0.0")

        resources = asyncio.run(mcp.list_resources())
        for r in resources:
            self.assertEqual(r.mime_type, "application/json")

        tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
        read_only_tools = (
            "get_security_status",
            "list_processes",
            "read_file",
            "list_directory",
            "search_files",
            "get_file_info",
            "get_system_info",
            "get_network_info",
            "get_environment",
            "get_clipboard",
        )
        for name in read_only_tools:
            ann = tools[name].annotations
            self.assertIsNotNone(ann, f"Missing ToolAnnotations on {name}")
            self.assertTrue(ann.read_only_hint, f"Expected read_only_hint=True on {name}")
            self.assertFalse(ann.destructive_hint, f"Expected destructive_hint=False on {name}")

        for name in ("execute_powershell", "execute_cmd", "execute_python", "delete_file_or_dir", "kill_process"):
            ann = tools[name].annotations
            self.assertIsNotNone(ann, f"Missing ToolAnnotations on {name}")
            self.assertFalse(ann.read_only_hint, f"Expected read_only_hint=False on {name}")
            self.assertTrue(ann.destructive_hint, f"Expected destructive_hint=True on {name}")

    def test_parse_arguments_default_stdio(self):
        """Verify that default CLI arguments specify strictly stdio transport."""
        with patch.object(sys, "argv", ["server.py"]):
            args = parse_arguments()
            self.assertEqual(args.transport, "stdio")
            self.assertEqual(args.log_level, "INFO")

    def test_parse_arguments_custom_log_level(self):
        """Verify custom log level parsing."""
        with patch.object(sys, "argv", ["server.py", "--log-level", "DEBUG"]):
            args = parse_arguments()
            self.assertEqual(args.transport, "stdio")
            self.assertEqual(args.log_level, "DEBUG")

    def test_parse_arguments_rejects_http_transport(self):
        """Verify that attempting to pass HTTP or remote transports is rejected."""
        with patch.object(sys, "argv", ["server.py", "--transport", "http"]):
            with self.assertRaises(SystemExit):
                with patch("sys.stderr", new_callable=io.StringIO):
                    parse_arguments()

    def test_stdio_cleanliness_stdout_untouched_by_logging(self):
        """Ensure logging is routed exclusively to stderr so stdout remains clean for MCP JSON-RPC."""
        stderr_capture = io.StringIO()
        stdout_capture = io.StringIO()

        test_handler = logging.StreamHandler(stderr_capture)
        test_handler.setLevel(logging.INFO)
        test_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.setLevel(logging.INFO)
        logger.addHandler(test_handler)

        try:
            with patch("sys.stdout", stdout_capture):
                logger.info("TEST_STDIO_LOG_MESSAGE")
                test_handler.flush()
                # stdout MUST be completely empty - zero log leakage
                self.assertEqual(stdout_capture.getvalue(), "")
                # stderr should contain our message
                self.assertIn("TEST_STDIO_LOG_MESSAGE", stderr_capture.getvalue())
        finally:
            logger.removeHandler(test_handler)

    def test_mcp_client_tool_invocation(self):
        """Test invoking an MCP tool through FastMCP Client in-memory harness."""
        async def run_test():
            async with Client(mcp) as client:
                res = await client.call_tool("get_security_status", {})
                self.assertTrue(res)
                data = res.data if hasattr(res, "data") else res
                self.assertIsNotNone(data)

        asyncio.run(run_test())

    def test_mcp_client_resource_read(self):
        """Test reading resources through FastMCP Client in-memory harness."""
        async def run_test():
            async with Client(mcp) as client:
                specs = await client.read_resource("system://specs")
                self.assertTrue(len(specs) > 0)
                self.assertEqual(specs[0].mime_type, "application/json")

                net = await client.read_resource("system://network")
                self.assertTrue(len(net) > 0)
                self.assertEqual(net[0].mime_type, "application/json")

        asyncio.run(run_test())

    def test_mcp_client_prompt_get(self):
        """Test retrieving prompts through FastMCP Client in-memory harness."""
        async def run_test():
            async with Client(mcp) as client:
                prompt = await client.get_prompt("system_health_check", {})
                self.assertTrue(prompt)
                self.assertTrue(len(prompt.messages) > 0)

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
