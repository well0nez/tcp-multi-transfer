#!/usr/bin/env python3
"""
TCP Hole Punch Relay Server - Starter Script
Simple wrapper to start the server as a module
"""
import sys
import subprocess

def main():
    """Run the server as a Python module, forwarding all arguments"""
    # Construct the command to run the server as a module
    cmd = [sys.executable, "-m", "server.main"] + sys.argv[1:]
    
    try:
        # Run the server and forward all output
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\nServer stopped by user")
        sys.exit(0)
    except subprocess.CalledProcessError as e:
        print(f"Server exited with error code {e.returncode}")
        sys.exit(e.returncode)
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()