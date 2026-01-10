#!/usr/bin/env python3
"""
PrivEsc-Framework Testing Script
Validates framework functionality and checks for false positives
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd):
    """Execute command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)

def test_basic_functionality():
    """Test basic framework functionality"""
    print("🧪 Testing Basic Functionality")
    print("-" * 40)
    
    # Test help
    code, stdout, stderr = run_command("python3 main.py --help")
    if code == 0:
        print("✅ Help command works")
    else:
        print("❌ Help command failed")
        return False
    
    # Test basic scan
    print("🔍 Running basic scan test...")
    code, stdout, stderr = run_command("python3 main.py -f txt")
    
    if code == 0:
        print("✅ Basic scan completed successfully")
        
        # Check for reasonable output
        if "PrivEsc-Framework v2.0" in stdout:
            print("✅ Framework banner present")
        else:
            print("⚠️  Framework banner missing")
        
        if "Total findings:" in stdout or "No privilege escalation" in stdout:
            print("✅ Scan results present")
        else:
            print("⚠️  Scan results unclear")
        
        return True
    else:
        print("❌ Basic scan failed")
        print(f"Error: {stderr}")
        return False

def test_false_positive_filtering():
    """Test false positive filtering"""
    print("\n🛡️  Testing False Positive Filtering")
    print("-" * 40)
    
    # Run scan and check for reasonable finding count
    code, stdout, stderr = run_command("python3 main.py -f json")
    
    if code == 0:
        # Look for finding count in output
        import re
        finding_match = re.search(r'Final findings: (\d+)', stdout)
        
        if finding_match:
            finding_count = int(finding_match.group(1))
            print(f"📊 Found {finding_count} findings")
            
            if finding_count < 100:  # Reasonable number
                print("✅ Finding count appears reasonable (< 100)")
                return True
            else:
                print("⚠️  High finding count - may have false positives")
                return False
        else:
            print("⚠️  Could not determine finding count")
            return False
    else:
        print("❌ False positive test failed")
        return False

def test_exploit_suggestions():
    """Test exploit suggestion feature"""
    print("\n💥 Testing Exploit Suggestions")
    print("-" * 40)
    
    code, stdout, stderr = run_command("python3 main.py -f txt -e")
    
    if code == 0:
        print("✅ Exploit suggestions feature works")
        
        if "exploit suggestions" in stdout.lower():
            print("✅ Exploit suggestions generated")
        else:
            print("ℹ️  No exploit suggestions (normal for secure systems)")
        
        return True
    else:
        print("❌ Exploit suggestions test failed")
        return False

def test_cross_platform_compatibility():
    """Test cross-platform compatibility"""
    print("\n🌐 Testing Cross-Platform Compatibility")
    print("-" * 40)
    
    import platform
    current_os = platform.system()
    print(f"📋 Current OS: {current_os}")
    
    # Test OS detection
    code, stdout, stderr = run_command("python3 -c \"from core.os_detector import OSDetector; print(OSDetector().detect())\"")
    
    if code == 0:
        print("✅ OS detection works")
        return True
    else:
        print("❌ OS detection failed")
        return False

def main():
    """Run all tests"""
    print("🚀 PrivEsc-Framework v2.0 Testing Suite")
    print("=" * 50)
    
    # Change to framework directory
    os.chdir(Path(__file__).parent)
    
    tests = [
        test_basic_functionality,
        test_false_positive_filtering,
        test_exploit_suggestions,
        test_cross_platform_compatibility
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
    
    print(f"\n📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Framework is ready for production.")
        return True
    else:
        print("⚠️  Some tests failed. Review issues before deployment.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)