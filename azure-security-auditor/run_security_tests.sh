#!/bin/bash
# Run all security tests in sequence

echo "🔐 Running Complete Security Test Suite"
echo ""

# 1. SAST - Test the tool code
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase 1: SAST (Testing the Security Auditor tool)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python sast_scan.py
SAST_EXIT=$?
echo ""

# 2. DAST - Test runtime security
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase 2: DAST (Testing runtime security)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python dast_scan.py
DAST_EXIT=$?
echo ""

# 3. Compliance - Test Azure infrastructure
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Phase 3: Azure Infrastructure Compliance Audit"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python cli.py -v
AUDIT_EXIT=$?
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SECURITY TEST SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "SAST (Tool Security):          $([ $SAST_EXIT -eq 0 ] && echo '✅ PASSED' || echo '❌ FAILED')"
echo "DAST (Runtime Security):       $([ $DAST_EXIT -eq 0 ] && echo '✅ PASSED' || echo '❌ FAILED')"
echo "Compliance (Infrastructure):   $([ $AUDIT_EXIT -eq 0 ] && echo '✅ PASSED' || echo '⚠️  FINDINGS')"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📄 Reports generated in: reports/"
echo "   - reports/bandit.json (SAST results)"
echo "   - reports/azure_audit.json (Compliance results)"
echo ""

# Exit with error if any critical failures
if [ $SAST_EXIT -ne 0 ]; then
    echo "❌ Security tests FAILED - Critical issues in tool code"
    exit 1
fi

echo "✅ All security tests complete!"
exit 0
