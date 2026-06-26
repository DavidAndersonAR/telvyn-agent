# Build do objeto eBPF do profiler de CPU, ISOLADO do L7 (internal/ebpf/Makefile).
# Compila cpuprofile.c em Docker (clang) e gera cpuprofile_bpf.go (cpuProfilerProgs)
# aqui no pacote cpuprofiler. Precisa de Docker (roda no macOS com Docker Desktop).
build:
	@echo ===BUILDING cpuprofiler===
	docker rmi -f cpuprofiler 2>/dev/null || true
	docker build -t cpuprofiler --progress plain .
	docker run --rm --name cpuprofiler cpuprofiler cat /tmp/ebpf/cpuprofile_bpf.go > ./cpuprofile_bpf.go
	@echo ===DONE===
