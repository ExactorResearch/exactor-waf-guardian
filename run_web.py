#!/usr/bin/env python3
"""Launch Exactor WAF Guardian Web Dashboard Server."""

import sys
import uvicorn

if __name__ == "__main__":
    port = 8002
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    print(f"\n========================================================")
    print(f" 🛡️  EXACTOR WAF GUARDIAN - Web Server")
    print(f" 🌐  Dashboard URL: http://localhost:{port}")
    print(f"========================================================\n")

    uvicorn.run("exactor_waf.web.server:app", host="0.0.0.0", port=port, reload=False)
