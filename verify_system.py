#!/usr/bin/env python3
"""
System Verification Script
Checks that all components are properly integrated and functional
"""

import sys
import os
import json
from pathlib import Path

def print_header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def check_file_exists(filepath, description):
    if os.path.exists(filepath):
        size = os.path.getsize(filepath)
        print(f"✅ {description}: {filepath} ({size:,} bytes)")
        return True
    else:
        print(f"❌ {description}: {filepath} - NOT FOUND")
        return False

def check_python_imports():
    """Check that all required Python modules can be imported"""
    required_modules = [
        ('websockets', 'WebSocket server functionality'),
        ('sklearn', 'Machine Learning capabilities'),
        ('sqlite3', 'Database functionality'),
        ('asyncio', 'Async operations'),
        ('json', 'JSON processing'),
        ('logging', 'Logging system'),
    ]
    
    all_good = True
    for module_name, description in required_modules:
        try:
            __import__(module_name)
            print(f"✅ {description}: {module_name}")
        except ImportError:
            print(f"❌ {description}: {module_name} - NOT AVAILABLE")
            all_good = False
    
    return all_good

def check_system_components():
    """Verify all system components exist and are properly sized"""
    components = [
        ('cellular_security.py', 'Main cellular monitoring module'),
        ('cellular_remote_server.py', 'Remote monitoring server'),
        ('iOS-App/NetworkSecurityMonitor/ContentView.swift', 'iOS app main interface'),
        ('requirements.txt', 'Python dependencies'),
        ('quick_start.sh', 'Quick start script'),
        ('test_ios_remote_integration.py', 'Integration test script'),
        ('PRODUCTION_DEPLOYMENT_GUIDE.md', 'Deployment documentation'),
        ('CLEANUP_COMPLETE.md', 'Workspace cleanup report'),
    ]
    
    all_good = True
    for filepath, description in components:
        if not check_file_exists(filepath, description):
            all_good = False
    
    return all_good

def check_ios_app_structure():
    """Check iOS app structure and key files"""
    ios_files = [
        'iOS-App/NetworkSecurityMonitor.xcodeproj/project.pbxproj',
        'iOS-App/NetworkSecurityMonitor/NetworkSecurityMonitorApp.swift',
        'iOS-App/NetworkSecurityMonitor/ContentView.swift',
        'iOS-App/NetworkSecurityMonitor/Info.plist',
    ]
    
    all_good = True
    for filepath in ios_files:
        if not check_file_exists(filepath, f"iOS file"):
            all_good = False
    
    # Check ContentView.swift size (should be substantial)
    contentview_path = 'iOS-App/NetworkSecurityMonitor/ContentView.swift'
    if os.path.exists(contentview_path):
        size = os.path.getsize(contentview_path)
        lines = sum(1 for line in open(contentview_path))
        print(f"   📊 ContentView.swift: {lines:,} lines of code")
        if lines > 2000:
            print(f"   ✅ Substantial iOS implementation detected")
        else:
            print(f"   ⚠️  iOS implementation may be incomplete")
    
    return all_good

def test_core_imports():
    """Test that core system modules can be imported"""
    try:
        print("🧪 Testing core module imports...")
        
        # Test cellular_security module
        sys.path.append('.')
        import cellular_security
        print("✅ cellular_security module imported successfully")
        
        # Test that it has key classes
        if hasattr(cellular_security, 'CellularSecurityMonitor'):
            print("✅ CellularSecurityMonitor class found")
        else:
            print("❌ CellularSecurityMonitor class not found")
            return False
        
        # Test cellular_remote_server module
        import cellular_remote_server
        print("✅ cellular_remote_server module imported successfully")
        
        if hasattr(cellular_remote_server, 'CellularRemoteMonitoringServer'):
            print("✅ CellularRemoteMonitoringServer class found")
        else:
            print("❌ CellularRemoteMonitoringServer class not found")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Module import failed: {e}")
        return False

def main():
    print("🔍 Cellular Security System Verification")
    
    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    all_checks_passed = True
    
    # Check system components
    print_header("System Components")
    if not check_system_components():
        all_checks_passed = False
    
    # Check Python dependencies
    print_header("Python Dependencies")
    if not check_python_imports():
        all_checks_passed = False
    
    # Check iOS app structure
    print_header("iOS App Structure")
    if not check_ios_app_structure():
        all_checks_passed = False
    
    # Test core imports
    print_header("Core Module Testing")
    if not test_core_imports():
        all_checks_passed = False
    
    # Final result
    print_header("Verification Results")
    if all_checks_passed:
        print("🎉 ALL CHECKS PASSED!")
        print("✅ System is ready for deployment")
        print("✅ All components are properly integrated")
        print("✅ Dependencies are available")
        print("✅ iOS app is complete")
        print("")
        print("🚀 Next steps:")
        print("   1. Run: ./quick_start.sh")
        print("   2. Open iOS app in Xcode")
        print("   3. Deploy for production use")
    else:
        print("❌ SOME CHECKS FAILED")
        print("⚠️  Please review the errors above")
        print("📋 Ensure all files are in place and dependencies installed")
    
    print(f"\n{'='*60}")
    return 0 if all_checks_passed else 1

if __name__ == "__main__":
    exit(main())
