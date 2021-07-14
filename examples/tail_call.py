from bcc import BPF
from ctypes import c_int, c_uint

# define BPF program
prog = """
BPF_PROG_ARRAY(prog_array, 10);

int tail_call(void *ctx) {
    bpf_trace_printk("Tail-call\\n");
    return 0;
}

int do_tail_call(void *ctx) {
    bpf_trace_printk("Original program starts\\n");
    prog_array.call(ctx, 2);
    bpf_trace_printk("Original program ends\\n");
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
tail_fn = b.load_func("tail_call", BPF.KPROBE)
prog_array = b.get_table("prog_array")
prog_array[c_int(2)] = c_int(tail_fn.fd)
#prog_array[c_int(3)] = c_int(tail_fn.fd)

b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="do_tail_call")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
