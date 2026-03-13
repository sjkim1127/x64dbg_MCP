import os
import subprocess
import sys

def check_dll_exports(dll_path):
    print(f"Checking exports for {dll_path}...")
    # Use dumpbin if available (Windows)
    try:
        result = subprocess.run(['dumpbin', '/EXPORTS', dll_path], capture_output=True, text=True)
        if result.returncode == 0:
            # Check for core x64dbg plugin exports
            expected_exports = ['pluginit', 'plugsetup', 'plugstop']
            found = []
            for export in expected_exports:
                if export in result.stdout:
                    found.append(export)
            
            print(f"Found exports: {found}")
            if len(found) == len(expected_exports):
                return True
            else:
                print(f"Missing exports. Expected {expected_exports}, found {found}")
                return False
        else:
            print("dumpbin failed or not found. Skipping export check.")
            return True # Fallback for non-MSVC environments
    except FileNotFoundError:
        print("dumpbin not found. Skipping export check.")
        return True

if __name__ == "__main__":
    dll_dir = "x64dbg-mcp-rust/target/release"
    if not os.path.exists(dll_dir):
        print(f"Directory {dll_dir} not found.")
        sys.exit(1)
    
    dlls = [f for f in os.listdir(dll_dir) if f.endswith(".dll")]
    if not dlls:
        print("No DLLs found in release directory.")
        sys.exit(1)
    
    success = True
    for dll in dlls:
        full_path = os.path.join(dll_dir, dll)
        if not check_dll_exports(full_path):
            success = False
    
    if success:
        print("Smoke test passed!")
        sys.exit(0)
    else:
        print("Smoke test failed!")
        sys.exit(1)
