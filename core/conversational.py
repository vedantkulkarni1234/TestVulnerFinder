"""Conversational AI interface powered by Gemini 2.5 Flash.

This module provides natural language interaction with Aurora, allowing users to
describe their scanning needs conversationally rather than using complex CLI flags.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from google import genai
from google.genai import types


@dataclass(slots=True)
class ConversationContext:
    """Maintains state across multi-turn conversations."""

    history: list[dict[str, str]] = field(default_factory=list)
    last_targets: list[str] = field(default_factory=list)
    last_modules: list[str] = field(default_factory=list)
    scan_preferences: dict[str, Any] = field(default_factory=dict)

    def add_message(self, role: str, content: str) -> None:
        """Add a message to conversation history."""
        self.history.append({"role": role, "content": content})

    def update_preferences(self, **kwargs: Any) -> None:
        """Update scan preferences from parsed intent."""
        self.scan_preferences.update(kwargs)


@dataclass(frozen=True, slots=True)
class ScanIntent:
    """Parsed user intent for a scan operation."""

    action: str  # scan, help, status, analyze, etc.
    targets: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)
    user_message: str = ""
    confidence: float = 1.0


# Function calling schema for Gemini
AURORA_FUNCTION_SCHEMA = [
    {
        "name": "scan_targets",
        "description": """Scan one or more targets for security vulnerabilities. Use this when the user
wants to analyze, scan, test, or check targets for vulnerabilities like Log4Shell, Spring4Shell, etc.
Examples: 'scan example.com', 'check https://test.com for log4shell', 'analyze these hosts for RCE'""",
        "parameters": {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of target URLs, hostnames, IP addresses, or CIDR ranges to scan",
                },
                "modules": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": """Detection modules to use. Available: spring4shell, log4shell, text4shell,
fastjson, jackson, struts2, kibana, ghostscript, vm2. Use 'all' or empty for all modules.""",
                },
                "enable_waf_bypass": {
                    "type": "boolean",
                    "description": "Enable WAF evasion techniques (Specter mode)",
                    "default": False,
                },
                "enable_stealth": {
                    "type": "boolean",
                    "description": "Enable stealth mode with randomized delays",
                    "default": False,
                },
                "enable_oast": {
                    "type": "boolean",
                    "description": "Enable out-of-band callback detection (Sonar mode)",
                    "default": False,
                },
                "concurrency": {
                    "type": "integer",
                    "description": "Number of concurrent workers (1-10000)",
                    "default": 200,
                },
                "output_format": {
                    "type": "string",
                    "enum": ["rich", "json", "markdown", "html"],
                    "description": "Output format for results",
                    "default": "rich",
                },
                "use_cidr": {
                    "type": "boolean",
                    "description": "Whether targets include CIDR notation",
                    "default": False,
                },
                "ports": {
                    "type": "string",
                    "description": "Ports to scan for CIDR targets (e.g., '80,443,8080-8090')",
                    "default": "80,443",
                },
            },
            "required": ["targets"],
        },
    },
    {
        "name": "get_scan_status",
        "description": """Get status of a running or recent scan. Use when user asks about progress,
current status, or results.""",
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "explain_vulnerability",
        "description": """Explain a specific vulnerability or CVE. Use when user asks 'what is X?',
'explain Y', 'tell me about Z vulnerability'.""",
        "parameters": {
            "type": "object",
            "properties": {
                "vulnerability_name": {
                    "type": "string",
                    "description": "Name of vulnerability (e.g., 'log4shell', 'spring4shell', 'CVE-2021-44228')",
                }
            },
            "required": ["vulnerability_name"],
        },
    },
    {
        "name": "list_capabilities",
        "description": """List Aurora's capabilities, modules, or features. Use when user asks
'what can you do?', 'help', 'list modules', 'show features'.""",
        "parameters": {
            "type": "object",
            "properties": {
                "detail_level": {
                    "type": "string",
                    "enum": ["brief", "detailed"],
                    "description": "Level of detail to provide",
                    "default": "brief",
                }
            },
        },
    },
    {
        "name": "configure_scan_preferences",
        "description": """Update default scan preferences. Use when user wants to set defaults like
'always use stealth mode', 'enable WAF bypass by default', etc.""",
        "parameters": {
            "type": "object",
            "properties": {
                "default_stealth": {"type": "boolean"},
                "default_waf_bypass": {"type": "boolean"},
                "default_oast": {"type": "boolean"},
                "default_concurrency": {"type": "integer"},
                "default_modules": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
        },
    },
]


SYSTEM_PROMPT = """You are AURORA Assistant, an intelligent security reconnaissance companion powered by
the AURORA tool - a high-confidence scanner for historic Java/Node.js RCE vulnerabilities.

Your role is to help security professionals and researchers conduct vulnerability scans through natural
conversation. You understand security concepts, vulnerability names (Log4Shell, Spring4Shell, Text4Shell,
Fastjson, Jackson, Struts2, Kibana, Ghostscript, VM2), and can translate user intent into appropriate
scan configurations.

Key capabilities:
- Scan targets for known RCE vulnerabilities
- Support for WAF evasion (Specter mode)
- Out-of-band callback detection (Sonar/OAST mode)
- Stealth scanning with randomized delays
- Distributed scanning across multiple workers
- CIDR range scanning
- Multi-format output (console, JSON, Markdown, HTML)

When users ask you to scan/analyze/check/test targets:
1. Parse their intent to extract targets, desired modules, and options
2. Use the scan_targets function with appropriate parameters
3. Provide conversational feedback about what you're doing
4. Explain findings in accessible terms

Be proactive: if a user mentions Log4Shell, suggest enabling OAST mode for better detection.
If they're scanning many targets, suggest appropriate concurrency levels.
If they mention firewalls or WAFs, suggest Specter mode.

Always prioritize security and ethical scanning - remind users to only scan authorized targets.

Keep responses concise but friendly. Use technical terms when appropriate but explain as needed."""


class GeminiConversationalRouter:
    """Handles natural language routing using Gemini 2.5 Flash."""

    def __init__(self, api_key: str | None = None) -> None:
        """Initialize Gemini client.

        Args:
            api_key: Google AI API key (or uses GOOGLE_API_KEY env var)
        """
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Gemini API key required. Set GOOGLE_API_KEY env var or pass api_key parameter."
            )

        self.client = genai.Client(api_key=self.api_key)
        self.model_id = "gemini-2.0-flash-exp"  # Using latest available model
        
        self.generation_config = types.GenerateContentConfig(
            temperature=0.3,
            top_p=0.95,
            top_k=40,
            max_output_tokens=2048,
            system_instruction=SYSTEM_PROMPT,
        )

    def _build_function_declarations(self) -> list[types.FunctionDeclaration]:
        """Build function declarations from schema for the new API."""
        declarations = []
        for func_schema in AURORA_FUNCTION_SCHEMA:
            declarations.append(
                types.FunctionDeclaration(
                    name=func_schema["name"],
                    description=func_schema["description"],
                    parameters=func_schema["parameters"],
                )
            )
        return declarations

    def parse_intent(self, user_message: str, context: ConversationContext) -> ScanIntent:
        """Parse user's natural language input into structured intent.

        Args:
            user_message: The user's conversational input
            context: Current conversation context for multi-turn awareness

        Returns:
            ScanIntent with parsed action and parameters
        """
        # Build conversation history for context
        contents = []
        for msg in context.history[-10:]:  # Last 10 messages for context
            role_map = {"user": "user", "assistant": "model"}
            contents.append(
                types.Content(
                    role=role_map.get(msg["role"], "user"),
                    parts=[types.Part(text=msg["content"])]
                )
            )

        # Add current message
        contents.append(
            types.Content(
                role="user",
                parts=[types.Part(text=user_message)]
            )
        )

        # Define tools for function calling
        tools = [types.Tool(function_declarations=self._build_function_declarations())]
        config = types.GenerateContentConfig(
            temperature=self.generation_config.temperature,
            top_p=self.generation_config.top_p,
            top_k=self.generation_config.top_k,
            max_output_tokens=self.generation_config.max_output_tokens,
            system_instruction=self.generation_config.system_instruction,
            tools=tools,
        )

        # Get response with function calling
        response = self.client.models.generate_content(
            model=self.model_id,
            contents=contents,
            config=config,
        )

        # Parse function call if present
        if response.candidates:
            for part in response.candidates[0].content.parts:
                if part.function_call:
                    return self._function_call_to_intent(part.function_call, user_message)

        # If no function call, it's a conversational response
        response_text = response.text if response.text else "I'm not sure how to help with that."
        return ScanIntent(
            action="respond",
            user_message=user_message,
            options={"response": response_text},
        )

    def _function_call_to_intent(
        self, function_call: Any, user_message: str
    ) -> ScanIntent:
        """Convert Gemini function call to ScanIntent."""
        name = function_call.name
        args = dict(function_call.args)

        action_map = {
            "scan_targets": "scan",
            "get_scan_status": "status",
            "explain_vulnerability": "explain",
            "list_capabilities": "help",
            "configure_scan_preferences": "configure",
        }

        action = action_map.get(name, "unknown")

        if action == "scan":
            return ScanIntent(
                action="scan",
                targets=args.get("targets", []),
                modules=args.get("modules", []),
                options={
                    "enable_waf_bypass": args.get("enable_waf_bypass", False),
                    "enable_stealth": args.get("enable_stealth", False),
                    "enable_oast": args.get("enable_oast", False),
                    "concurrency": args.get("concurrency", 200),
                    "output_format": args.get("output_format", "rich"),
                    "use_cidr": args.get("use_cidr", False),
                    "ports": args.get("ports", "80,443"),
                },
                user_message=user_message,
            )

        return ScanIntent(
            action=action,
            options=args,
            user_message=user_message,
        )

    def generate_response(
        self, user_message: str, context: ConversationContext, result_data: dict[str, Any] | None = None
    ) -> str:
        """Generate a conversational response to user.

        Args:
            user_message: User's input
            context: Conversation context
            result_data: Optional data from executed action (e.g., scan results)

        Returns:
            Natural language response
        """
        contents = []
        for msg in context.history[-10:]:
            role_map = {"user": "user", "assistant": "model"}
            contents.append(
                types.Content(
                    role=role_map.get(msg["role"], "user"),
                    parts=[types.Part(text=msg["content"])]
                )
            )

        # Add result context if available
        prompt = user_message
        if result_data:
            prompt += f"\n\n[SYSTEM: Action completed. Result summary: {json.dumps(result_data, indent=2)}]"

        contents.append(
            types.Content(
                role="user",
                parts=[types.Part(text=prompt)]
            )
        )

        response = self.client.models.generate_content(
            model=self.model_id,
            contents=contents,
            config=self.generation_config,
        )

        return response.text if response.text else "Operation completed."
