"""
Emon DSL libbpf Loader Generator

Generates a user-space C loader from an IRProgram.
The loader uses libbpf skeleton-based loading and handles:
  - BPF program loading and attaching
  - Ring buffer event polling
  - Periodic every-task map reading and printing
  - begin/end lifecycle hooks
  - Command-line option parsing

Corresponds to project plan sections 5.4.7.
"""

from typing import List

from emon.ir import IRProgram, IREveryTask, IRPrint


def _safe_c_name(name: str) -> str:
    """Convert a name to a valid C identifier."""
    return name.replace("@", "").replace("-", "_").replace(".", "_")


class LoaderGenerator:
    """Generates a user-space libbpf loader C file."""

    def __init__(self, ir: IRProgram):
        self.ir = ir
        # Build option lookup, stripping outer quotes from string values
        self._opt_map: dict = {}
        for o in ir.options:
            val = o.get("default", "0")
            # Strip outer quotes from string literal values
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            self._opt_map[o["name"]] = val

    def _get_option_value(self, name: str) -> str:
        """Get the default value of an option by name."""
        return self._opt_map.get(name, "0")

    def generate(self) -> str:
        """Generate the complete *_loader.c source."""
        parts: List[str] = []
        parts.append(self._emit_header())
        parts.append(self._emit_includes())
        parts.append(self._emit_globals())
        parts.append(self._emit_event_handler())
        parts.append(self._emit_option_variables())
        parts.append(self._emit_map_printers())
        parts.append(self._emit_main())
        return "\n\n".join(parts) + "\n"

    # ------------------------------------------------------------------
    # Header comment
    # ------------------------------------------------------------------

    def _emit_header(self) -> str:
        tool = _safe_c_name(self.ir.tool_name)
        return f"""\
// =====================================================================
// {tool}_loader.c -- Emon DSL 生成的用户态 libbpf 加载器
// 工具名称: {self.ir.tool_name}
//
// 编译步骤:
//   1. clang -O2 -g -target bpf -c {tool}.bpf.c -o {tool}.bpf.o
//   2. bpftool gen skeleton {tool}.bpf.o > {tool}.skel.h
//   3. gcc {tool}_loader.c -o {tool}_loader -lbpf -lelf -lz
//
// 本文件由 Emon DSL 编译器自动生成，请勿手动编辑。
// ====================================================================="""

    def _emit_includes(self) -> str:
        tool = _safe_c_name(self.ir.tool_name)
        return f"""\
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "{tool}.skel.h"

// ---- Event struct (mirrors BPF side definition) ----
{self._emit_loader_event_structs()}"""

    def _emit_globals(self) -> str:
        tool = _safe_c_name(self.ir.tool_name)
        return f"""\
static volatile sig_atomic_t __stop = 0;
static void __sigint_handler(int sig) {{
    (void)sig;
    __stop = 1;
}}

static struct {tool}_bpf *__skel = NULL;
static struct ring_buffer *__rb = NULL;

// Use sigaction instead of signal() to avoid SA_RESTART,
// which prevents Ctrl+C from interrupting sleep().
static void __setup_signals(void) {{
    struct sigaction sa = {{0}};
    sa.sa_handler = __sigint_handler;
    sa.sa_flags = 0;  // no SA_RESTART
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}}"""

    # ------------------------------------------------------------------
    # Event handler (ring buffer callback)
    # ------------------------------------------------------------------

    def _emit_loader_event_structs(self) -> str:
        """Generate C struct definitions for events (mirrors BPF side)."""
        if not self.ir.events:
            return ""
        parts = []
        for ev in self.ir.events:
            name = ev.name.replace("-", "_").replace(".", "_")
            lines = [f"struct {name} {{"]
            for field in ev.fields:
                fname = field["name"].replace("-", "_").replace(".", "_")
                ftype = field["type"]
                # Map types to C types for user-space
                if "char" in ftype:
                    # Extract array size: "char [16]" -> "char fname[16]"
                    if "[" in ftype:
                        base, size = ftype.split("[", 1)
                        size = size.rstrip("] ")
                        lines.append(f"    char {fname}[{size}];")
                    else:
                        lines.append(f"    char {fname}[64];")
                elif ftype in ("u64", "__u64"):
                    lines.append(f"    unsigned long long {fname};")
                elif ftype in ("u32", "__u32"):
                    lines.append(f"    unsigned int {fname};")
                elif ftype in ("s64", "__s64"):
                    lines.append(f"    long long {fname};")
                else:
                    lines.append(f"    unsigned long long {fname};")
            lines.append("};")
            parts.append("\n".join(lines))
        return "\n".join(parts) + "\n"

    def _emit_event_handler(self) -> str:
        if not self.ir.events:
            return "// No emit events defined"

        ev = self.ir.events[0]
        ev_name = _safe_c_name(ev.name)

        # Generate field printers
        field_prints: List[str] = []
        for field in ev.fields:
            fname = field["name"]
            ftype = field["type"]
            if "char" in ftype:
                field_prints.append(
                    f'    fprintf(stderr, "  {fname}=%s\\n", e->{_safe_c_name(fname)});')
            else:
                field_prints.append(
                    f'    fprintf(stderr, "  {fname}=%llu\\n", '
                    f'(unsigned long long)e->{_safe_c_name(fname)});')

        fp = "\n".join(field_prints)

        return f"""\
// ---- Ring Buffer Event Handler ----
static int __handle_event(void *ctx, void *data, size_t data_sz) {{
    (void)ctx;
    const struct {ev_name} *e = data;
    fprintf(stderr, "[{self.ir.tool_name}] event (size=%zu):\\n", data_sz);
{fp}
    return 0;
}}"""

    # ------------------------------------------------------------------
    # Option variables (from command line)
    # ------------------------------------------------------------------

    def _emit_option_variables(self) -> str:
        if not self.ir.options:
            return "// No options"

        lines: List[str] = ["// ---- Options (configurable at startup) ----"]
        for opt in self.ir.options:
            name = opt["name"]
            default = self._opt_map.get(name, "0")
            # Escape backslashes and double quotes for C string literal
            escaped = default.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'static const char *__opt_{name} = "{escaped}";')
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Map printers (used by every-task and end block)
    # ------------------------------------------------------------------

    def _emit_map_printers(self) -> str:
        lines: List[str] = []
        lines.append("// ---- Map dump helpers ----")
        lines.append(r"""
// Helper: print a key - shows comm-like prefix + hex for binary parts
static void __print_key(const unsigned char *key, int key_size) {
    // Print first 16 bytes as string if they look like a comm name
    int i, str_end = 0;
    for (i = 0; i < key_size && i < 16; i++) {
        if (key[i] == 0) { str_end = i; break; }
        if (key[i] < 32 || key[i] > 126) { str_end = -1; break; }
    }
    if (str_end > 0) {
        fprintf(stdout, "%.*s ", str_end, (const char *)key);
    }
    // Print remaining bytes as hex
    for (i = (str_end > 0 ? 16 : 0); i < key_size && i < 36; i++)
        fprintf(stdout, "%02x", key[i]);
}

// Sum a PERCPU value across all CPUs
static __u64 __percpu_sum(const void *value_ptr, int val_size, int nr_cpus, int offset) {
    __u64 total = 0;
    int cpu;
    const unsigned char *base = (const unsigned char *)value_ptr;
    for (cpu = 0; cpu < nr_cpus; cpu++)
        total += *(__u64 *)(base + cpu * val_size + offset);
    return total;
}
""")

        for m in self.ir.maps:
            map_safe = _safe_c_name(m.name)
            is_percpu = "PERCPU" in m.map_type.upper()
            is_avg = "avg" in m.name.lower()
            is_hist = "hist" in m.name.lower()
            lines.append(f"""
static void __print_map_{map_safe}(int top_n) {{
    if (!__skel) return;
    struct bpf_map *map = __skel->maps.{map_safe};
    if (!map) {{ fprintf(stderr, "map '{m.name}' not found\\n"); return; }}

    int fd = bpf_map__fd(map);
    if (fd < 0) return;

    int key_size = (int)bpf_map__key_size(map);
    if (key_size <= 0 || key_size > 64) key_size = 64;
    int nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus <= 0) nr_cpus = 1;
    int val_size = (int)bpf_map__value_size(map);
    if (val_size <= 0) val_size = 8;

    unsigned char key[64];
    unsigned char next_key[64];
    // PERCPU maps need val_size * nr_cpus bytes for lookup_elem.
    // Use stack buffer for small values, heap for large (nr_cpus can be 128+).
    int total_val = val_size * nr_cpus;
    unsigned char stack_buf[4096];
    unsigned char *value_buf = stack_buf;
    int use_heap = 0;
    if (total_val > (int)sizeof(stack_buf)) {{
        value_buf = (unsigned char *)malloc(total_val);
        if (!value_buf) {{
            fprintf(stderr, "map '{m.name}': malloc(%d) failed\\n", total_val);
            return;
        }}
        use_heap = 1;
    }}
    int buf_size = use_heap ? total_val : (int)sizeof(stack_buf);
    memset(key, 0, sizeof(key));
    memset(next_key, 0, sizeof(next_key));
    memset(value_buf, 0, buf_size);
    int count = 0;

    fprintf(stdout, "\\n-- @{m.name} --\\n");

    int err = bpf_map_get_next_key(fd, NULL, next_key);
    while (err == 0) {{
        memcpy(key, next_key, key_size);
        memset(value_buf, 0, buf_size);
        if (bpf_map_lookup_elem(fd, key, value_buf) == 0) {{
            count++;
            if (top_n <= 0 || count <= top_n) {{
                fprintf(stdout, "  [%4d] key=", count);
                __print_key(key, key_size);""")
            if is_hist:
                lines.append(f"""\
                // Histogram: sum buckets across CPUs
                int n_buckets = val_size / 8;
                if (n_buckets > 64) n_buckets = 64;
                int b;
                for (b = 0; b < n_buckets; b++) {{
                    __u64 bucket_val = __percpu_sum(value_buf, val_size, nr_cpus, b * 8);
                    if (bucket_val > 0) {{
                        fprintf(stdout, "  bucket[%2d] = %llu ", b, (unsigned long long)bucket_val);
                        int bar = (int)(bucket_val > 40 ? 40 : bucket_val);
                        int j;
                        for (j = 0; j < bar; j++) fputc('#', stdout);
                        fputc('\\n', stdout);
                    }}
                }}""")
            elif is_avg:
                lines.append(f"""\
                __u64 sum = __percpu_sum(value_buf, val_size, nr_cpus, 0);
                __u64 cnt = __percpu_sum(value_buf, val_size, nr_cpus, 8);
                if (cnt > 0)
                    fprintf(stdout, "  avg=%llu (n=%llu)\\n",
                            (unsigned long long)(sum / cnt), (unsigned long long)cnt);
                else
                    fprintf(stdout, "  avg=N/A\\n");""")
            elif is_percpu:
                lines.append(f"""\
                __u64 val = __percpu_sum(value_buf, val_size, nr_cpus, 0);
                fprintf(stdout, "  val=%llu\\n", (unsigned long long)val);""")
            else:
                lines.append(f"""\
                __u64 val = *(__u64*)value_buf;
                fprintf(stdout, "  val=%llu\\n", (unsigned long long)val);""")
            lines.append(f"""\
            }}
        }}
        err = bpf_map_get_next_key(fd, key, next_key);
    }}

    if (count == 0)
        fprintf(stdout, "  (empty)\\n");
    else
        fprintf(stdout, "  total: %d entries\\n", count);

    if (use_heap) free(value_buf);
}}
""")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Main function
    # ------------------------------------------------------------------

    def _emit_main(self) -> str:
        tool = _safe_c_name(self.ir.tool_name)

        # Option declarations
        opt_decls = ""
        opt_init = ""
        if self.ir.options:
            opt_lines = []
            opt_init_lines = []
            for opt in self.ir.options:
                name = opt["name"]
                default = self._opt_map.get(name, "0")
                escaped = default.replace("\\", "\\\\").replace('"', '\\"')
                opt_lines.append(f'    const char *{name} = "{escaped}";')
                opt_init_lines.append(
                    f'    fprintf(stderr, "  option {name} = %s\\n", {name});')
            opt_decls = "\n".join(opt_lines)
            opt_init = "\n".join(opt_init_lines)

        # Begin block
        begin_code = self._emit_begin_end_block("begin", self.ir.begin_stmts)

        # End block
        end_code = self._emit_begin_end_block("end", self.ir.end_stmts)

        # Every-task loop body
        every_body = self._emit_every_loop()

        # Ring buffer setup
        rb_setup = ""
        rb_poll = ""
        rb_destroy = ""
        if self.ir.events:
            ev_name = _safe_c_name(self.ir.events[0].name)
            rb_name = _safe_c_name(f"{ev_name}_rb")
            rb_setup = f"""\
    // ---- Ring buffer for emit events ----
    __rb = ring_buffer__new(bpf_map__fd(__skel->maps.{rb_name}),
                            __handle_event, NULL, NULL);
    if (!__rb) {{
        fprintf(stderr, "Failed to create ring buffer\\n");
        goto cleanup;
    }}"""
            rb_poll = f"""\
        // Poll ring buffer for events
        ring_buffer__poll(__rb, 100);"""
            rb_destroy = "    ring_buffer__free(__rb);"

        return f"""\
// =====================================================================
// main
// =====================================================================

int main(int argc, char **argv) {{
    int err;

    (void)argc; (void)argv;
{opt_decls}

    fprintf(stderr, "[{self.ir.tool_name}] Emon DSL monitor starting...\\n");

    // ---- Signal handlers ----
    __setup_signals();

    // ---- Load BPF skeleton ----
    __skel = {tool}_bpf__open();
    if (!__skel) {{
        fprintf(stderr, "Failed to open BPF skeleton\\n");
        return 1;
    }}

    // ---- Apply options to BPF program (if needed) ----
{opt_init}

    // ---- Load BPF programs ----
    err = {tool}_bpf__load(__skel);
    if (err) {{
        fprintf(stderr, "Failed to load BPF skeleton: %d\\n", err);
        goto cleanup;
    }}

    // ---- Attach BPF programs ----
    err = {tool}_bpf__attach(__skel);
    if (err) {{
        fprintf(stderr, "Failed to attach BPF skeleton: %d\\n", err);
        goto cleanup;
    }}
    fprintf(stderr, "[{self.ir.tool_name}] BPF programs loaded and attached.\\n");

{rb_setup}

    // ---- begin block ----
{begin_code}

    // ---- Main event loop (every tasks) ----
    fprintf(stderr, "[{self.ir.tool_name}] Running (Ctrl+C to stop)...\\n");
    while (!__stop) {{
{every_body}
{rb_poll}
    }}

    // ---- end block ----
{end_code}

{self._emit_default_end_dump()}
    fprintf(stderr, "[{self.ir.tool_name}] Shutting down.\\n");

cleanup:
{rb_destroy}
    if (__skel) {{
        {tool}_bpf__destroy(__skel);
        __skel = NULL;
    }}
    return 0;
}}"""

    def _emit_default_end_dump(self) -> str:
        """If no explicit end block, dump all maps as a summary before exit."""
        if self.ir.end_stmts:
            return ""  # User has an explicit end block
        if not self.ir.maps:
            return ""  # No maps to dump

        lines = ["    // ---- Default end: dump all maps ----",
                 '    fprintf(stdout, "\\n==== Final Report ====\\n");']
        for m in self.ir.maps:
            map_safe = _safe_c_name(m.name)
            lines.append(f"    __print_map_{map_safe}(20);")
        return "\n".join(lines)

    def _emit_begin_end_block(self, kind: str, stmts: List[IRPrint]) -> str:
        """Generate code for begin/end lifecycle blocks."""
        if not stmts:
            return f"    // No {kind} block"

        lines = [f"    // ---- {kind} block ----"]
        for stmt in stmts:
            expr = stmt.expr
            # Check if it's a string literal
            if expr.startswith('"') and expr.endswith('"'):
                inner = expr[1:-1]
                lines.append(f'    fprintf(stdout, "{inner}\\n");')
            else:
                lines.append(f'    fprintf(stdout, "  {expr}\\n");')
        return "\n".join(lines)

    def _emit_every_loop(self) -> str:
        """Generate the every-task polling loop body."""
        if not self.ir.every_tasks:
            # No every task: just poll in small chunks for Ctrl+C responsiveness
            return """\
        int __i;
        for (__i = 0; __i < 4 && !__stop; __i++)
            usleep(50000);  // 50ms * 4 = 200ms"""

        # For simplicity, merge all every-tasks with the first interval
        task = self.ir.every_tasks[0]
        interval = task.interval

        # Convert time literal to seconds
        sleep_sec = self._interval_to_seconds(interval)

        lines: List[str] = []
        lines.append("        // ---- every task ----")
        lines.append("        static time_t __last_tick = 0;")
        lines.append("        time_t __now = time(NULL);")
        lines.append(f"        if (__now - __last_tick >= {sleep_sec}) {{")
        lines.append("            __last_tick = __now;")

        for pr in task.prints:
            expr = pr.expr
            if expr.startswith('"') and expr.endswith('"'):
                inner = expr[1:-1]
                lines.append(f'            fprintf(stdout, "{inner}\\n");')
            elif expr.startswith("@") and "(" not in expr:
                # Simple @agg reference — just print the name for now
                agg_name = expr.lstrip("@")
                map_safe = _safe_c_name(agg_name)
                lines.append(f"            __print_map_{map_safe}(10);")
            elif expr.startswith("top("):
                # top(@agg, N) → call print with top_n
                lines.append(f"            // top query: {expr}")
                inner = expr[4:-1]  # strip "top(" and ")"
                parts_inner = inner.rsplit(",", 1)
                if len(parts_inner) == 2:
                    agg_ref = parts_inner[0].strip().lstrip("@")
                    top_n = parts_inner[1].strip()
                    map_safe = _safe_c_name(agg_ref)
                    # Resolve: if top_n is a number, use directly.
                    # If it's an option name, look up its value.
                    if top_n.isdigit():
                        n_val = top_n
                    else:
                        # Look up option value
                        opt_val = self._get_option_value(top_n)
                        n_val = opt_val if opt_val.isdigit() else "10"
                    lines.append(f"            __print_map_{map_safe}({n_val});")
                else:
                    lines.append(f"            fprintf(stdout, \"  {expr}\\n\");")
            else:
                lines.append(f'            fprintf(stdout, "  {expr}\\n");')

        lines.append("        }")
        lines.append(f"        // Small sleep chunks for Ctrl+C responsiveness")
        lines.append(f"        int __j;")
        lines.append(f"        for (__j = 0; __j < {max(1, sleep_sec * 20)} && !__stop; __j++)")
        lines.append(f"            usleep(50000);  // 50ms")

        return "\n".join(lines)

    def _interval_to_seconds(self, interval: str) -> int:
        """Convert a time literal string to seconds (integer)."""
        interval = interval.strip()
        if interval.endswith("ns"):
            return max(1, int(interval[:-2]) // 1_000_000_000)
        elif interval.endswith("us"):
            return max(1, int(interval[:-2]) // 1_000_000)
        elif interval.endswith("ms"):
            return max(1, int(interval[:-2]) // 1000)
        elif interval.endswith("s"):
            return max(1, int(interval[:-1]))
        # Try raw number (assume seconds)
        try:
            return max(1, int(interval))
        except ValueError:
            return 1


# =============================================================================
# Convenience
# =============================================================================

def generate_loader_c(ir: IRProgram) -> str:
    """Generate a complete libbpf loader C source from an IRProgram."""
    return LoaderGenerator(ir).generate()
