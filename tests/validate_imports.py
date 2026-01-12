# tests/validate_imports.py
import sys
import os
from pathlib import Path

def validate_imports():
    """Validate that the application can be imported"""
    print("=" * 60)
    print("ARF API Import Validation")
    print("=" * 60)
    
    # Get paths
    repo_root = Path(__file__).parent.parent
    src_path = repo_root / 'src'
    
    # Add to Python path
    sys.path.insert(0, str(repo_root))
    sys.path.insert(0, str(src_path))
    
    # Set environment
    os.environ['SKIP_DATABASE_INIT'] = '1'
    os.environ['TESTING'] = '1'
    os.environ['VALIDATION_MODE'] = '1'
    
    print(f"Repository root: {repo_root}")
    print(f"Python path: {sys.path[:2]}")
    print()
    
    try:
        # Try absolute import first (original style)
        from src.main import app
        print("✅ Import successful using absolute imports")
    except ImportError:
        try:
            # Try relative import (after we fix the source)
            # This simulates running from within src directory
            original_cwd = os.getcwd()
            os.chdir(str(src_path))
            sys.path.insert(0, str(src_path))
            
            from main import app
            print("✅ Import successful using relative imports")
            os.chdir(original_cwd)
        except Exception as e:
            print(f"❌ Import failed: {e}")
            return False
    
    print(f"   App: {app.title} v{app.version}")
    print(f"   Routes: {len(app.routes)}")
    return True

if __name__ == "__main__":
    success = validate_imports()
    sys.exit(0 if success else 1)
