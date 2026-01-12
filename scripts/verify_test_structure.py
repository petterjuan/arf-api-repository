# scripts/verify_test_structure.py
import os
import ast
from pathlib import Path
from typing import Dict, List, Set

def analyze_test_coverage():
    """Analyze test coverage and structure."""
    src_dir = Path("src")
    tests_dir = Path("tests")
    
    # Get all Python modules in src
    src_modules = set()
    for root, dirs, files in os.walk(src_dir):
        for file in files:
            if file.endswith('.py') and file != '__init__.py':
                rel_path = os.path.relpath(os.path.join(root, file), src_dir)
                module_name = rel_path.replace('.py', '').replace('/', '.')
                src_modules.add(module_name)
    
    # Get all test files
    test_files = {}
    for test_file in tests_dir.glob("test_*.py"):
        with open(test_file, 'r') as f:
            content = f.read()
        
        # Parse test file to find test functions
        tree = ast.parse(content)
        test_functions = [
            node.name for node in ast.walk(tree) 
            if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')
        ]
        
        # Check for pytest markers
        markers = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                if isinstance(node.value.func, ast.Attribute):
                    if node.value.func.attr == 'mark':
                        if node.value.args:
                            marker = node.value.args[0].s
                            markers.add(marker)
        
        test_files[test_file.name] = {
            'functions': len(test_functions),
            'markers': list(markers)
        }
    
    print("=== Test Coverage Analysis ===")
    print(f"\nSource modules found: {len(src_modules)}")
    for module in sorted(src_modules):
        print(f"  - {module}")
    
    print(f"\nTest files found: {len(test_files)}")
    total_tests = 0
    for filename, info in test_files.items():
        total_tests += info['functions']
        print(f"\n{filename}:")
        print(f"  Test functions: {info['functions']}")
        print(f"  Markers: {', '.join(info['markers']) if info['markers'] else 'None'}")
    
    print(f"\n=== Summary ===")
    print(f"Total test functions: {total_tests}")
    print(f"Average tests per module: {total_tests / len(src_modules):.1f}" if src_modules else "No source modules")
    
    # Check for integration tests
    integration_tests = sum(1 for info in test_files.values() if 'integration' in info['markers'])
    print(f"Integration test files: {integration_tests}")
    
    # Recommendations
    print(f"\n=== Recommendations ===")
    if total_tests < 20:
        print("⚠️  Consider adding more test cases")
    if integration_tests < 2:
        print("⚠️  Need more integration tests")
    if any('integration' not in info['markers'] for info in test_files.values()):
        print("⚠️  Some test files missing pytest markers")

if __name__ == "__main__":
    analyze_test_coverage()
