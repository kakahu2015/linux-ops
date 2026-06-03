#!/bin/bash
# check-kernel-patches.sh
# Check if jp/sjc have kernel updates that might contain CVE-2026-31431 fix

SKILL_DIR=~/.openclaw/workspace/skills/linux-ops

echo "=== $(date -u '+%Y-%m-%d %H:%M UTC') Kernel Patch Check ==="
echo ""

for host_tag in japan sjc; do
    echo "--- $host_tag ---"
    
    # Check current kernel
    CURRENT=$(cd "$SKILL_DIR" && bash scripts/runner.sh --target "tag=$host_tag" --cmd "uname -r" --parallel 1 --timeout 30 2>/dev/null)
    KERNEL=$(echo "$CURRENT" | grep -oP '"stdout":\s*"\K[^"]+' | head -1)
    echo "Current kernel: $KERNEL"
    
    # Check available kernel updates (try dnf/yum/apt)
    RESULT=$(cd "$SKILL_DIR" && bash scripts/runner.sh --target "tag=$host_tag" --cmd "
        if command -v dnf &>/dev/null; then
            dnf check-update kernel* 2>/dev/null | grep -i kernel
        elif command -v yum &>/dev/null; then
            yum check-update kernel* 2>/dev/null | grep -i kernel
        elif command -v apt &>/dev/null; then
            apt list --upgradable 2>/dev/null | grep -i linux-image
        else
            echo 'unknown package manager'
        fi
    " --parallel 1 --timeout 30 2>/dev/null)
    
    AVAILABLE=$(echo "$RESULT" | grep -oP '"stdout":\s*"\K[^"]+' | head -1)
    
    if [ -z "$AVAILABLE" ] || echo "$AVAILABLE" | grep -qi "error\|blocked\|refused\|timeout"; then
        echo "Update check: UNABLE TO VERIFY (SSH issue or no updates found)"
        echo "Action: Manual check recommended on $host_tag"
    elif echo "$AVAILABLE" | grep -qi "kernel"; then
        echo "NEW KERNEL AVAILABLE: $AVAILABLE"
        echo "ACTION NEEDED: Update and reboot $host_tag"
    else
        echo "Update check: No kernel updates available yet"
    fi
    
    echo ""
done

echo "=== Check complete ==="
