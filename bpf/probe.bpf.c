#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const u32 zero = 0;

struct event {
    u64 pid_tgid;
    u8 comm[80];
};

#if USE_RING_BUF

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

#endif /* if USE_RING_BUF */

#if USE_PERF_BUF

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1 << 14); // size is os.PageSize * max_entries // TODO: confirm this
} perf_events SEC(".maps");

/*
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(struct other_event))
  __uint(max_entries, 1);
} other_event_heap SEC(".maps");
*/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct event));
    __uint(max_entries, 1);
} event_heap SEC(".maps");

#endif /* if USE_PERF_BUF */

SEC("tracepoint/syscalls/sys_enter_sendto")
int BPF_PROG(sys_enter_sendto) {
    u64 id = bpf_get_current_pid_tgid();
    struct event *task_info;

#if USE_RING_BUF

    task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!task_info) {
        return 0;
    }

    task_info->pid_tgid = id;
    bpf_get_current_comm(&task_info->comm, 80);

    bpf_ringbuf_submit(task_info, 0);

#endif /* if USE_RING_BUF */

#if USE_PERF_BUF

    task_info = bpf_map_lookup_elem(&event_heap, &zero);
    if (task_info == NULL) {
        return 0;
    }

    // struct event task_info_full = { 0 };

    task_info->pid_tgid = id;
    bpf_get_current_comm(&task_info->comm, 80);

    bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, task_info, sizeof(struct event));

#endif /* if USE_PERF_BUF */
    return 0;
};

char _license[] SEC("license") = "Dual Apache/GPL";
