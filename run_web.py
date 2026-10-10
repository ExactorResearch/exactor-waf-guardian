#!/usr/bin/env python3
"""Launch Exactor WAF Guardian Web Dashboard Server."""

import sys
import uvicorn

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

if __name__ == "__main__":
    port = 8002
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    print("\n" + "=" * 60)
    print(" [WEB] EXACTOR WAF GUARDIAN - Web Server")
    print(f" [URL] Dashboard: http://localhost:{port}")
    print("=" * 60 + "\n")

    uvicorn.run("exactor_waf.web.server:app", host="0.0.0.0", port=port, reload=False)
