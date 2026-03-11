# ZeroTrace Agent Debugging Summary

## 1. Issue Description
**Symptom**: The ZeroTrace Agent panicked with an overflow error.
**Log Snippet**:
```text
[2026-03-05 11:39:23.401931 +00:00] ERROR [src/main.rs:128] panicked at src/policy/labeler.rs:73:27:
attempt to shift left with overflow
```

## 2. Root Cause Analysis
The panic occurs in `src/policy/labeler.rs` within the `EpcNetIpKey::clone_by_masklen` method.
```rust
ip: self.ip & (u128::MAX << max_prefix.saturating_sub(masklen)),
```
For IPv6, `max_prefix` is 128. When `masklen` is 0, the shift amount becomes 128. Shifting a `u128` by 128 bits is undefined behavior/overflow in Rust, causing the panic in debug mode.

## 3. Solution
Modified the code to check if the shift amount equals or exceeds the type width (128 bits).

**File**: `/home/ubuntu/smore/zerotrace/agent/src/policy/labeler.rs`

**Change**:
```rust
    fn clone_by_masklen(&self, masklen: usize, is_ipv4: bool) -> Self {
        let max_prefix = if is_ipv4 { IPV4_BITS } else { IPV6_BITS };
        let shift = max_prefix.saturating_sub(masklen);
        let mask = if shift >= 128 {
            0
        } else {
            u128::MAX << shift
        };

        Self {
            ip: self.ip & mask,
            epc_id: self.epc_id,
            masklen: masklen as u8,
        }
    }
```

## 4. Verification

### 4.1 Reproduction Test Case
Added a test case `test_clone_by_masklen_panic` to `src/policy/labeler.rs` to reproduce the issue.
```rust
    #[test]
    fn test_clone_by_masklen_panic() {
        let ip6 = "2002:2002::10";
        let key = EpcNetIpKey::new(&ip6.parse().unwrap(), 128, 10);
        let _ = key.clone_by_masklen(0, false);
    }
```

### 4.2 Test Execution (Docker)
Executed the test in the provided Docker build environment.

**Command**:
```bash
docker run --privileged --rm -v /home/ubuntu/smore/zerotrace:/zerotrace -v ~/.cargo:/usr/local/cargo hub.zerotrace.yunshan.net/public/rust-build bash -c "cd /zerotrace/agent && cargo test --package zerotrace-agent --lib test_clone_by_masklen_panic"
```

**Result**:
```text
running 1 test
test policy::labeler::tests::test_clone_by_masklen_panic ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 240 filtered out; finished in 0.00s
```

## 5. Diagnostic Command Summary
During the investigation, the following commands were used to diagnose agent status and port usage.

| Command | Purpose | Result (Historical) |
|---------|---------|---------------------|
| `ps aux | grep zerotrace-agent` | Check agent process status | Found running agent (pid 2408689) |
| `grep "debugger listening on" agent.log` | Find debugger port | Port 13779 |
| `zerotrace-agent-ctl -p 13779 ebpf datadump ...` | Capture eBPF data | Captured HTTP/TCP traffic successfully |
| `tail -n 100 agent.log` | Check for recent errors | Found panic log |

