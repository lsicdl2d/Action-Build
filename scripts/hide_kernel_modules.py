#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hide selected kernel modules from non-root readers of /proc/modules.

Injects a per-reader filter into kernel/module/procfs.c so that ordinary app
UIDs (uid >= 10000) do not see the listed modules in /proc/modules.
Modules keep loading and working normally -- only the listing is filtered.

Same design idea as SukiSU's mount_hide: filter by reader, do not unload.

Idempotent. Fails loudly if anchors are missing.

Usage:
    python3 hide_kernel_modules.py [source_root] [comma,separated,module,names]
"""

import os
import sys

MARKER = "ksu_module_should_hide"

DEFAULT_MODULES = "rekernel,bbg,ntsync,kernelsu,ksu,susfs"

INCLUDES = """#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/string.h>
"""

HELPER_TMPL = """
/*
 * Hide selected modules from non-root readers of /proc/modules.
 * Modules stay loaded and functional; only the listing is filtered.
 */
static const char *const ksu_hidden_modules[] = {
%s
};

static bool ksu_module_should_hide(const char *name)
{
\tuid_t uid = current_euid().val;
\tint i;

\t/* Keep the real view for root and system daemons. */
\tif (uid < 10000)
\t\treturn false;

\tfor (i = 0; i < ARRAY_SIZE(ksu_hidden_modules); i++) {
\t\tif (!strcmp(name, ksu_hidden_modules[i]))
\t\t\treturn true;
\t}

\treturn false;
}

"""

DECL_BLOCK = (
    "\tstruct module *mod = list_entry(p, struct module, list);\n"
    "\tchar buf[MODULE_FLAGS_BUF_SIZE];\n"
    "\tvoid *value;\n"
)

GUARD = (
    "\n\tif (module_is_live(mod) && ksu_module_should_hide(mod->name))\n"
    "\t\treturn 0;\n"
)

SHOW_SIG = "static int m_show(struct seq_file *m, void *p)"
INCLUDE_ANCHOR = '#include "internal.h"'


def die(msg):
    sys.stderr.write("[hide_kernel_modules] ERROR: %s\n" % msg)
    sys.exit(1)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    names_arg = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("HIDE_MODULE_NAMES", DEFAULT_MODULES)

    names = [n.strip() for n in names_arg.split(",") if n.strip()]
    if not names:
        die("empty module name list")

    path = os.path.join(root, "kernel", "module", "procfs.c")
    if not os.path.isfile(path):
        alt = os.path.join(root, "common", "kernel", "module", "procfs.c")
        if os.path.isfile(alt):
            path = alt
        else:
            die("cannot find kernel/module/procfs.c under %r" % root)

    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        src = f.read()

    if MARKER in src:
        print("[hide_kernel_modules] already applied, skipping: %s" % path)
        return 0

    helper = HELPER_TMPL % "\n".join('\t"%s",' % n for n in names)

    if INCLUDE_ANCHOR not in src:
        die("include anchor %r not found in %s" % (INCLUDE_ANCHOR, path))
    src = src.replace(INCLUDE_ANCHOR, INCLUDES + "\n" + INCLUDE_ANCHOR, 1)

    if src.count(SHOW_SIG) != 1:
        die("m_show() signature count=%d in %s" % (src.count(SHOW_SIG), path))
    src = src.replace(SHOW_SIG, helper + SHOW_SIG, 1)

    if src.count(DECL_BLOCK) != 1:
        die("m_show() declaration block count=%d in %s" % (src.count(DECL_BLOCK), path))
    src = src.replace(DECL_BLOCK, DECL_BLOCK + GUARD, 1)

    with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write(src)

    print("[hide_kernel_modules] patched: %s" % path)
    print("[hide_kernel_modules] hidden modules: %s" % ", ".join(names))
    return 0


if __name__ == "__main__":
    sys.exit(main())
