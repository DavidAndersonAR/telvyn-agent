FROM alpine:3.14

RUN apk add llvm clang libbpf-dev linux-headers

COPY ebpf /tmp/ebpf
WORKDIR /tmp/ebpf

# O programa de profiling não usa tracepoints nem o layout que pede
# __CTX_EXTRA_PADDING, e não tem código dependente da versão do kernel — só
# perf_event + pt_regs. Então basta 1 .o por arquitetura (piso 4.16, igual ao L7).
RUN clang -g -O2 -target bpf -D__TARGET_ARCH_x86   -c cpuprofile.c -o cpuprofilex86.o   && llvm-strip --strip-debug cpuprofilex86.o
RUN clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -c cpuprofile.c -o cpuprofilearm64.o && llvm-strip --strip-debug cpuprofilearm64.o

# Mesma estrutura do ebpf.go do L7 (map por arch de {version,flags,prog}), mas com
# nome de var e package PRÓPRIOS — zero colisão com ebpfProgs. 1 entrada por arch.
# Atenção: aqui o package JÁ sai certo (`cpuprofiler`), sem o gotcha do ebpf.go.
RUN echo -en '// generated - do not edit\npackage cpuprofiler\n\nvar cpuProfilerProgs = map[string][]struct {\n' > cpuprofile_bpf.go \
	&& echo -en '\tversion string\n' >> cpuprofile_bpf.go \
	&& echo -en '\tflags   string\n' >> cpuprofile_bpf.go \
	&& echo -en '\tprog    []byte\n' >> cpuprofile_bpf.go \
	&& echo -en '}{\n' >> cpuprofile_bpf.go \
	&& echo -en '\t"amd64": {\n' >> cpuprofile_bpf.go \
	&& echo -en '\t\t{"4.16", "", []byte("' >> cpuprofile_bpf.go && gzip -c cpuprofilex86.o | base64 -w0 >> cpuprofile_bpf.go && echo '")},' >> cpuprofile_bpf.go \
	&& echo -en '\t},\n'>> cpuprofile_bpf.go \
	&& echo -en '\t"arm64": {\n' >> cpuprofile_bpf.go \
	&& echo -en '\t\t{"4.16", "", []byte("' >> cpuprofile_bpf.go && gzip -c cpuprofilearm64.o | base64 -w0 >> cpuprofile_bpf.go && echo '")},' >> cpuprofile_bpf.go \
	&& echo -en '\t},\n'>> cpuprofile_bpf.go \
	&& echo -en '}\n'>> cpuprofile_bpf.go
