#!/usr/bin/env python3
"""Basic tests for conversational interface without API calls."""

from core.conversational import (
    AURORA_FUNCTION_SCHEMA,
    ConversationContext,
    ScanIntent,
)


def test_conversation_context():
    """Test ConversationContext functionality."""
    ctx = ConversationContext()
    
    # Test adding messages
    ctx.add_message("user", "Hello")
    ctx.add_message("assistant", "Hi there!")
    
    assert len(ctx.history) == 2
    assert ctx.history[0]["role"] == "user"
    assert ctx.history[0]["content"] == "Hello"
    
    # Test updating preferences
    ctx.update_preferences(stealth=True, concurrency=500)
    assert ctx.scan_preferences["stealth"] is True
    assert ctx.scan_preferences["concurrency"] == 500
    
    # Test target tracking
    ctx.last_targets = ["example.com", "test.com"]
    assert len(ctx.last_targets) == 2
    
    print("✓ ConversationContext tests passed")


def test_scan_intent():
    """Test ScanIntent creation."""
    intent = ScanIntent(
        action="scan",
        targets=["example.com"],
        modules=["log4shell", "spring4shell"],
        options={"enable_waf_bypass": True},
        user_message="scan example.com",
    )
    
    assert intent.action == "scan"
    assert len(intent.targets) == 1
    assert len(intent.modules) == 2
    assert intent.options["enable_waf_bypass"] is True
    
    print("✓ ScanIntent tests passed")


def test_function_schema():
    """Test function schema is properly defined."""
    assert len(AURORA_FUNCTION_SCHEMA) > 0
    
    # Check scan_targets function
    scan_func = next(f for f in AURORA_FUNCTION_SCHEMA if f["name"] == "scan_targets")
    assert scan_func is not None
    assert "description" in scan_func
    assert "parameters" in scan_func
    assert "targets" in scan_func["parameters"]["properties"]
    
    # Check explain_vulnerability function
    explain_func = next(f for f in AURORA_FUNCTION_SCHEMA if f["name"] == "explain_vulnerability")
    assert explain_func is not None
    assert "vulnerability_name" in explain_func["parameters"]["properties"]
    
    print("✓ Function schema tests passed")


def test_module_imports():
    """Test that all required modules can be imported."""
    try:
        from core.conversational import GeminiConversationalRouter
        from core.engine import Engine, ScanConfig, Target
        from modules.log4shell import Log4ShellModule
        import aurora_chat
        print("✓ Module import tests passed")
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        raise


if __name__ == "__main__":
    print("Running basic conversational interface tests...\n")
    
    test_conversation_context()
    test_scan_intent()
    test_function_schema()
    test_module_imports()
    
    print("\n" + "=" * 60)
    print("All basic tests passed! ✨")
    print("=" * 60)
    print("\nNote: These tests don't require an API key.")
    print("To test full functionality, set GOOGLE_API_KEY and run:")
    print("  python examples/conversational_demo.py")
