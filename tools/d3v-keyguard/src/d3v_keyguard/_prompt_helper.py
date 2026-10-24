"""Isolated tkinter dialog. Reads a JSON request on stdin, writes a JSON reply on stdout."""

import json
import sys


def main() -> int:
    request = json.loads(sys.stdin.read())
    import tkinter as tk
    from tkinter import messagebox, simpledialog

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    title = str(request.get("title", "d3v-keyguard"))[:80]
    message = str(request.get("message", ""))[:1500]
    if request.get("kind") == "confirm":
        ok = messagebox.askyesno(title, message, parent=root)
        root.destroy()
        sys.stdout.write(json.dumps({"ok": bool(ok)}))
        return 0
    value = simpledialog.askstring(title, message, show="*", parent=root)
    root.destroy()
    if not value:
        return 2
    sys.stdout.write(json.dumps({"value": value}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
