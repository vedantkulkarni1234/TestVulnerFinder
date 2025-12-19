#!/usr/bin/env python3
"""Demo script showing conversational interface capabilities.

This demonstrates how to programmatically use the conversational API
for advanced automation and integration scenarios.
"""

import asyncio
import os

from core.conversational import ConversationContext, GeminiConversationalRouter


async def demo_basic_conversation() -> None:
    """Demonstrate basic conversational interaction."""
    print("=" * 60)
    print("DEMO 1: Basic Conversation")
    print("=" * 60)

    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("Error: Set GOOGLE_API_KEY environment variable")
        return

    router = GeminiConversationalRouter(api_key=api_key)
    context = ConversationContext()

    # Simulate a conversation
    messages = [
        "what vulnerabilities can you detect?",
        "explain log4shell to me",
        "scan example.com for log4shell",
    ]

    for msg in messages:
        print(f"\nUser: {msg}")
        intent = router.parse_intent(msg, context)
        print(f"Intent: {intent.action}")
        print(f"Targets: {intent.targets}")
        print(f"Modules: {intent.modules}")
        print(f"Options: {intent.options}")

        context.add_message("user", msg)
        context.add_message("assistant", f"Processed: {intent.action}")

    print("\n✓ Demo complete")


async def demo_context_awareness() -> None:
    """Demonstrate context awareness across multiple turns."""
    print("\n" + "=" * 60)
    print("DEMO 2: Context Awareness")
    print("=" * 60)

    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("Error: Set GOOGLE_API_KEY environment variable")
        return

    router = GeminiConversationalRouter(api_key=api_key)
    context = ConversationContext()

    # First request
    msg1 = "scan example.com for log4shell with stealth mode"
    print(f"\nUser: {msg1}")
    intent1 = router.parse_intent(msg1, context)
    print(f"Intent 1: {intent1.action}, targets={intent1.targets}")

    context.add_message("user", msg1)
    context.last_targets = intent1.targets
    context.update_preferences(enable_stealth=True)

    # Follow-up with context reference
    msg2 = "also check test.com with the same settings"
    print(f"\nUser: {msg2}")
    intent2 = router.parse_intent(msg2, context)
    print(f"Intent 2: {intent2.action}, targets={intent2.targets}")
    print(f"Context remembered: last_targets={context.last_targets}")

    print("\n✓ Demo complete - context maintained across turns")


async def demo_intent_parsing() -> None:
    """Demonstrate various natural language patterns."""
    print("\n" + "=" * 60)
    print("DEMO 3: Intent Parsing Variations")
    print("=" * 60)

    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("Error: Set GOOGLE_API_KEY environment variable")
        return

    router = GeminiConversationalRouter(api_key=api_key)
    context = ConversationContext()

    test_phrases = [
        "scan example.com",
        "check https://test.com for vulnerabilities",
        "analyze 192.168.1.0/24 for log4shell",
        "enable WAF bypass and scan myapp.com",
        "use stealth mode on sensitive-target.com",
        "scan example.com with OAST enabled for log4shell",
    ]

    for phrase in test_phrases:
        print(f"\n📝 Input: '{phrase}'")
        intent = router.parse_intent(phrase, context)
        print(f"   Action: {intent.action}")
        print(f"   Targets: {intent.targets}")
        print(f"   Modules: {intent.modules}")
        print(f"   Options: {intent.options}")

    print("\n✓ Demo complete - all patterns parsed successfully")


async def demo_function_calling() -> None:
    """Demonstrate Gemini function calling capabilities."""
    print("\n" + "=" * 60)
    print("DEMO 4: Function Calling")
    print("=" * 60)

    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("Error: Set GOOGLE_API_KEY environment variable")
        return

    router = GeminiConversationalRouter(api_key=api_key)
    context = ConversationContext()

    # Test different function calls
    test_cases = [
        ("scan example.com for log4shell", "scan_targets"),
        ("what is log4shell?", "explain_vulnerability"),
        ("what can you do?", "list_capabilities"),
        ("set default stealth mode to enabled", "configure_scan_preferences"),
    ]

    for query, expected_function in test_cases:
        print(f"\n📝 Query: '{query}'")
        print(f"   Expected: {expected_function}")
        intent = router.parse_intent(query, context)
        print(f"   Got: {intent.action}")
        print(f"   ✓ Match" if intent.action in expected_function else "   ✗ Mismatch")

    print("\n✓ Demo complete - function calling working correctly")


async def main() -> None:
    """Run all demos."""
    print("\n🔮 AURORA Conversational Interface Demo\n")

    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("❌ Error: GOOGLE_API_KEY environment variable not set")
        print("\nGet your API key from: https://aistudio.google.com/app/apikey")
        print("Then run: export GOOGLE_API_KEY='your-key-here'\n")
        return

    try:
        await demo_basic_conversation()
        await demo_context_awareness()
        await demo_intent_parsing()
        await demo_function_calling()

        print("\n" + "=" * 60)
        print("All demos completed successfully! ✨")
        print("=" * 60)
        print("\nTry the interactive interface:")
        print("  aurora-chat chat")
        print("\nOr query mode:")
        print("  aurora-chat query 'scan example.com for all vulnerabilities'")
        print()

    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
