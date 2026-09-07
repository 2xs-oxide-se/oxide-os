"""GDB helper for Cortex-M stack frame size inspection.

Usage from GDB:

    (gdb) source scripts/stack_dump.py
    (gdb) stack-dump
"""

import re

import gdb


_ARGLIST_RE = re.compile(r"Arglist at\s+(0x[0-9a-fA-F]+)")


def _frame_cfa(frame):
    """Return the best CFA-like address GDB exposes for a frame."""
    try:
        frame_info = gdb.execute(f"info frame {frame.level()}", to_string=True)
        for line in frame_info.splitlines():
            match = _ARGLIST_RE.search(line)
            if match:
                return int(match.group(1), 16)
    except gdb.error:
        pass

    try:
        return int(frame.read_register("sp"))
    except gdb.error:
        return None


class StackSizeDump(gdb.Command):
    """Print the call stack with CFA-based frame sizes."""

    def __init__(self):
        super(StackSizeDump, self).__init__("stack-dump", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        frame = gdb.newest_frame()
        print(f"{'#':<3} {'Function':<48} {'Address':<18} {'Frame Size':<12}")
        print("-" * 85)

        while frame:
            name = frame.name() or "???"
            pc = hex(frame.pc())
            level = frame.level()
            cfa = _frame_cfa(frame)

            older = frame.older()
            if older is None:
                size = "Bottom"
            else:
                older_cfa = _frame_cfa(older)
                if cfa is None or older_cfa is None:
                    size = "Unknown"
                else:
                    # Cortex-M stacks grow downward; older frames usually have a
                    # higher CFA. Keep the absolute value so interrupted frames
                    # still produce readable diagnostics.
                    size = f"{abs(older_cfa - cfa)} bytes"

            print(f"{level:<3} {name:<48} {pc:<18} {size:<12}")
            frame = older


StackSizeDump()
