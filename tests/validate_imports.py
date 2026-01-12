# tests/validate_imports.py
import sys
import os

# Set environment variables to prevent database initialization
os.environ['SKIP_DATABASE_INIT'] = '1'
os.environ['TESTING'] = '1'

# Add src to path
sys.path.insert(0, os.path.join(os.getcwd(), 'src'))

def main():
    print("=" * 60)
    print("ARF API Import Validation")
    print("=" * 60)
    
    try:
        from main import app
        print("✅ PASS: main.py imports successfully")
        print(f"   - App: {app.title} v{app.version}")
        print(f"   - Routes: {len(app.routes)}")
        return True
    except Exception as e:
        print(f"❌ FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
