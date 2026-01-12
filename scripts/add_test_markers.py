# scripts/add_test_markers.py
import os
import re
from pathlib import Path

def add_pytest_markers_to_tests():
    """Add pytest markers to existing test files."""
    tests_dir = Path("tests")
    
    # Map test files to appropriate markers
    test_markers = {
        "test_auth.py": ["@pytest.mark.auth", "@pytest.mark.unit"],
        "test_basic.py": ["@pytest.mark.unit"],
        "test_execution_ladder.py": ["@pytest.mark.integration", "@pytest.mark.database"],
        "test_incidents.py": ["@pytest.mark.integration", "@pytest.mark.database"],
        "test_monitoring.py": ["@pytest.mark.unit"],
        "test_rollback.py": ["@pytest.mark.integration", "@pytest.mark.database"],
    }
    
    for test_file, markers in test_markers.items():
        filepath = tests_dir / test_file
        if filepath.exists():
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Check if imports include pytest
            if "import pytest" not in content:
                # Add pytest import at the beginning
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if line.startswith('import ') or line.startswith('from '):
                        continue
                    if line.strip():
                        # Insert pytest import before first non-import line
                        lines.insert(i, "import pytest")
                        break
                content = '\n'.join(lines)
            
            # Add markers to test functions
            lines = content.split('\n')
            new_lines = []
            
            for line in lines:
                new_lines.append(line)
                # Look for test function definitions
                if line.strip().startswith('def test_') and '(' in line:
                    # Add markers on the line before the function
                    indent = len(line) - len(line.lstrip())
                    for marker in markers:
                        new_lines.insert(-1, ' ' * indent + marker)
            
            # Write back if changes were made
            new_content = '\n'.join(new_lines)
            if new_content != content:
                with open(filepath, 'w') as f:
                    f.write(new_content)
                print(f"Updated markers in {test_file}")
            else:
                print(f"No changes needed for {test_file}")

if __name__ == "__main__":
    add_pytest_markers_to_tests()
