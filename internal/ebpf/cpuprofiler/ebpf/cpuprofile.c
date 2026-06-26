// cpuprofile.c — perfilador de CPU por amostragem (estilo BCC `profile` / Pyroscope).
//
// Coleção eBPF SEPARADA do tracer L7 (proc/file/tcp/l7): compila num .o próprio,
// carrega numa *ebpf.Collection própria, e roda atrás do toggle
// ISPWATCH_PROFILING_ENABLED. Se o verifier rejeitar num kernel, só o profiler
// fica off — o L7 nunca é tocado.
//
// Ideia: um programa BPF_PROG_TYPE_PERF_EVENT disparado por um perf_event de
// PERF_COUNT_SW_CPU_CLOCK a ~N Hz POR CPU. A cada disparo, captura a pilha de
// kernel e de user do processo corrente (bpf_get_stackid) e incrementa um
// histograma counts[(pid, kstack, ustack, comm)] += 1. O user-space drena
// `counts` + `stacks` por janela, simboliza e dobra em folded stacks por serviço.
//
// Perfila TODOS os processos do nó (objetivo = "host inteiro"); a atribuição a
// serviço/pod é feita no user-space (PID -> container -> service). Só pula o
// idle/swapper (tgid 0).

#include <uapi/linux/bpf.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN      16
#define MAX_STACK_DEPTH    127     // teto do kernel (PERF_MAX_STACK_DEPTH)
#define MAX_STACK_TRACES   16384   // nº de pilhas únicas guardadas
#define MAX_COUNT_ENTRIES  65536   // nº de (pid,kstack,ustack,comm) únicos

// Contexto do programa perf_event. O vmlinux.h mínimo do repo não traz
// `bpf_perf_event_data` (sem BTF/CO-RE), então definimos aqui sobre o pt_regs
// que o vmlinux.h já declara por arch. Só passamos `ctx` pro bpf_get_stackid
// (que o trata como void*), não lemos os regs diretamente.
typedef struct pt_regs bpf_user_pt_regs_t;
struct bpf_perf_event_data {
    bpf_user_pt_regs_t regs;
    __u64 sample_period;
    __u64 addr;
};

// Chave do histograma: identifica uma pilha completa amostrada.
struct sample_key {
    __u32 pid;                    // tgid (o "processo")
    __s64 kern_stack_id;          // stackid kernel (-1 = ausente/erro)
    __s64 user_stack_id;          // stackid user   (-1 = ausente/erro)
    char  comm[TASK_COMM_LEN];    // fallback de rótulo
};

// stacks: o kernel preenche com os IPs e devolve um id estável por pilha.
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_STACK_TRACES);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stacks SEC(".maps");

// counts: histograma sample_key -> nº de amostras.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_COUNT_ENTRIES);
    __uint(key_size, sizeof(struct sample_key));
    __uint(value_size, sizeof(__u64));
} counts SEC(".maps");

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx) {
    __u64 id   = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;

    if (tgid == 0)               // idle/swapper — ignora
        return 0;

    struct sample_key key = {};
    key.pid = tgid;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    // Duas chamadas separadas: kernel (sem flag) e user (BPF_F_USER_STACK).
    // <0 = sem pilha (falha de unwind, kernel idle, etc.) — guardado como tal.
    key.kern_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    key.user_stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);

    __u64 *val = bpf_map_lookup_elem(&counts, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&counts, &key, &one, BPF_NOEXIST);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";   // bpf_get_stackid exige GPL
