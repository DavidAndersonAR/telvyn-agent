// mutate.go — handler do /mutate endpoint. Decodifica AdmissionReview,
// inspeciona o Pod, decide se injeta -javaagent + volume + env vars,
// devolve JSONPatch.

package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// AdmissionReview / Pod minimalista — só os campos que consumimos.
// Evita dependência em k8s.io/api (~10MB de tipos). O api-server aceita
// JSON canonical, então struct simples já basta.

type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

type AdmissionRequest struct {
	UID       string `json:"uid"`
	Kind      struct {
		Group   string `json:"group"`
		Version string `json:"version"`
		Kind    string `json:"kind"`
	} `json:"kind"`
	Namespace string          `json:"namespace"`
	Name      string          `json:"name"`
	Operation string          `json:"operation"`
	Object    json.RawMessage `json:"object"`
}

type AdmissionResponse struct {
	UID     string `json:"uid"`
	Allowed bool   `json:"allowed"`
	// Patch é []byte de propósito: o k8s exige o JSONPatch BASE64-encoded no
	// campo response.patch, e encoding/json serializa []byte como base64. Usar
	// json.RawMessage mandaria o array cru → apiserver não decodifica e (com
	// failurePolicy=Ignore) admite o pod SEM a injeção, silenciosamente.
	Patch     []byte `json:"patch,omitempty"`
	PatchType string `json:"patchType,omitempty"`
}

type podMeta struct {
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations,omitempty"`
		GenerateName string           `json:"generateName,omitempty"`
		OwnerReferences []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"ownerReferences,omitempty"`
	} `json:"metadata"`
	Spec struct {
		Containers     []container `json:"containers"`
		InitContainers []container `json:"initContainers,omitempty"`
		Volumes        []volume    `json:"volumes,omitempty"`
	} `json:"spec"`
}

type container struct {
	Name         string       `json:"name"`
	Image        string       `json:"image"`
	Env          []envVar     `json:"env,omitempty"`
	VolumeMounts []volumeMount `json:"volumeMounts,omitempty"`
}

type envVar struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	ValueFrom *struct {
		FieldRef *struct {
			FieldPath string `json:"fieldPath"`
		} `json:"fieldRef,omitempty"`
	} `json:"valueFrom,omitempty"`
}

type volume struct {
	Name     string                 `json:"name"`
	EmptyDir map[string]interface{} `json:"emptyDir,omitempty"`
}

type volumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

// JSONPatch operation.
type patchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func (s *Server) handleMutate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var review AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "decode review: "+err.Error(), http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		http.Error(w, "missing request", http.StatusBadRequest)
		return
	}
	resp := s.decide(review.Request)
	out := AdmissionReview{
		APIVersion: review.APIVersion,
		Kind:       review.Kind,
		Response:   resp,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// decide aplica a regra: pod com (ns, name) ativado no backend +
// container Java? injeta. Senão, allow sem patch.
//
// Pod controllers (ReplicaSet/StatefulSet) criam pods com generateName
// + hash. O nome real só existe na hora do CREATE. Por isso fazemos
// match também por prefixo do generateName + ownerReferences.
func (s *Server) decide(req *AdmissionRequest) *AdmissionResponse {
	out := &AdmissionResponse{UID: req.UID, Allowed: true}

	if req.Kind.Kind != "Pod" {
		return out
	}
	var pod podMeta
	if err := json.Unmarshal(req.Object, &pod); err != nil {
		s.cfg.Log.Warn("webhook decode pod failed", "err", err)
		return out
	}
	ns := req.Namespace
	if ns == "" {
		ns = pod.Metadata.Namespace
	}
	workload, ok := s.matchWorkload(pod, ns)
	if !ok {
		return out
	}
	javaContainers := findJavaContainers(pod.Spec.Containers)
	if len(javaContainers) == 0 {
		s.cfg.Log.Debug("webhook: workload marcado mas sem container Java", "ns", ns, "workload", workload)
		return out
	}

	patch := buildPatch(pod, javaContainers, s.cfg.AgentImage, s.cfg.OtlpEndpointEnv, s.cfg.OtlpProtocol, workload)
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		s.cfg.Log.Warn("webhook patch marshal failed", "err", err)
		return out
	}
	out.Patch = patchBytes
	out.PatchType = "JSONPatch"
	s.cfg.Log.Info("webhook: injetou javaagent", "ns", ns, "workload", workload, "pod", podDisplayName(pod), "containers", len(javaContainers))
	return out
}

// matchWorkload deriva o(s) workload(s) candidato(s) do pod sendo criado e
// confere contra o enable map (chaveado por "ns/workload"). Como o backend
// marca por WORKLOAD, isto sobrevive a rollout (ReplicaSet novo) e restart —
// ao contrário de casar por nome de pod. No CREATE o pod normalmente só tem
// generateName + ownerReferences (o nome real ainda não existe), então
// derivamos o workload dos três.
func (s *Server) matchWorkload(pod podMeta, ns string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, wl := range candidateWorkloads(pod) {
		if _, ok := s.enable[ns+"/"+wl]; ok {
			return wl, true
		}
	}
	return "", false
}

// candidateWorkloads gera os nomes de workload possíveis pro pod, cobrindo
// Deployment (generateName "app-<rs>-" / ownerRef ReplicaSet "app-<rs>"),
// StatefulSet/DaemonSet (ownerRef "app") e o caso de o nome já estar setado.
// O sufixo "00000" finge um pod-hash pra reaproveitar workloadOf nos nomes
// sem sufixo (generateName/ReplicaSet).
func candidateWorkloads(pod podMeta) []string {
	seen := map[string]struct{}{}
	out := []string{}
	add := func(w string) {
		if w == "" {
			return
		}
		if _, ok := seen[w]; ok {
			return
		}
		seen[w] = struct{}{}
		out = append(out, w)
	}
	if pod.Metadata.Name != "" {
		add(workloadOf(pod.Metadata.Name))
	}
	if gn := pod.Metadata.GenerateName; gn != "" {
		add(workloadOf(gn + "00000"))                // Deployment: "app-<rs>-" → "app"
		add(workloadOf(strings.TrimSuffix(gn, "-"))) // StatefulSet generateName "app-"
	}
	for _, o := range pod.Metadata.OwnerReferences {
		add(workloadOf(o.Name))            // StatefulSet/DaemonSet name
		add(workloadOf(o.Name + "-00000")) // ReplicaSet "app-<rs>" → "app"
	}
	return out
}

// findJavaContainers heurística: image contém keyword Java ou env já
// expõe JAVA_TOOL_OPTIONS.
func findJavaContainers(in []container) []int {
	out := []int{}
	kw := []string{"java", "jdk", "openjdk", "temurin", "corretto", "graalvm", "quarkus"}
	for i, c := range in {
		img := strings.ToLower(c.Image)
		matched := false
		for _, k := range kw {
			if strings.Contains(img, k) {
				matched = true
				break
			}
		}
		if !matched {
			for _, e := range c.Env {
				if e.Name == "JAVA_TOOL_OPTIONS" || e.Name == "JAVA_OPTS" {
					matched = true
					break
				}
			}
		}
		if matched {
			out = append(out, i)
		}
	}
	return out
}

func podDisplayName(p podMeta) string {
	if p.Metadata.Name != "" {
		return p.Metadata.Name
	}
	return p.Metadata.GenerateName + "<generated>"
}

// buildPatch gera o JSONPatch que:
//  1. adiciona volume emptyDir 'ispwatch-otel'
//  2. prepend initContainer 'ispwatch-otel-init' que copia o jar
//  3. adiciona volumeMount nos containers Java
//  4. adiciona env vars OTel + JAVA_TOOL_OPTIONS nos containers Java
//     (sem sobrescrever se cliente já tem JAVA_TOOL_OPTIONS — append)
func buildPatch(pod podMeta, javaIdx []int, agentImage, otlpEnvValue, otlpProtocol, serviceName string) []patchOp {
	ops := []patchOp{}

	// Volume
	if pod.Spec.Volumes == nil || len(pod.Spec.Volumes) == 0 {
		ops = append(ops, patchOp{
			Op: "add", Path: "/spec/volumes",
			Value: []volume{{Name: "ispwatch-otel", EmptyDir: map[string]interface{}{}}},
		})
	} else {
		ops = append(ops, patchOp{
			Op: "add", Path: "/spec/volumes/-",
			Value: volume{Name: "ispwatch-otel", EmptyDir: map[string]interface{}{}},
		})
	}

	// initContainer
	initCt := map[string]interface{}{
		"name":            "ispwatch-otel-init",
		"image":           agentImage,
		"imagePullPolicy": "IfNotPresent",
		"command":         []string{"sh", "-c", "cp /opt/otel/javaagent.jar /otel/javaagent.jar && chmod 0644 /otel/javaagent.jar"},
		"volumeMounts":    []volumeMount{{Name: "ispwatch-otel", MountPath: "/otel"}},
		"resources": map[string]interface{}{
			"requests": map[string]string{"cpu": "10m", "memory": "16Mi"},
			"limits":   map[string]string{"cpu": "100m", "memory": "32Mi"},
		},
	}
	if pod.Spec.InitContainers == nil || len(pod.Spec.InitContainers) == 0 {
		ops = append(ops, patchOp{Op: "add", Path: "/spec/initContainers", Value: []interface{}{initCt}})
	} else {
		ops = append(ops, patchOp{Op: "add", Path: "/spec/initContainers/-", Value: initCt})
	}

	// Para cada container Java: volumeMount + env vars
	for _, idx := range javaIdx {
		c := pod.Spec.Containers[idx]

		// VolumeMount
		mount := volumeMount{Name: "ispwatch-otel", MountPath: "/otel", ReadOnly: true}
		if c.VolumeMounts == nil || len(c.VolumeMounts) == 0 {
			ops = append(ops, patchOp{
				Op:    "add",
				Path:  containerPath(idx, "/volumeMounts"),
				Value: []volumeMount{mount},
			})
		} else {
			ops = append(ops, patchOp{
				Op:    "add",
				Path:  containerPath(idx, "/volumeMounts/-"),
				Value: mount,
			})
		}

		// JAVA_TOOL_OPTIONS: se o container já define, faz REPLACE anexando o
		// -javaagent (não sobrescreve o que o cliente pôs); senão entra no add.
		const agentOpt = "-javaagent:/otel/javaagent.jar"
		jtoIdx := -1
		for i, e := range c.Env {
			if e.Name == "JAVA_TOOL_OPTIONS" {
				jtoIdx = i
				break
			}
		}

		// Env vars OTel (sem JAVA_TOOL_OPTIONS — tratado à parte acima).
		envs := []envVar{
			{Name: "NODE_IP", ValueFrom: fieldRef("status.hostIP")},
			{Name: "POD_NAME", ValueFrom: fieldRef("metadata.name")},
			{Name: "POD_NAMESPACE", ValueFrom: fieldRef("metadata.namespace")},
			{Name: "OTEL_EXPORTER_OTLP_ENDPOINT", Value: otlpEnvValue},
			{Name: "OTEL_EXPORTER_OTLP_PROTOCOL", Value: otlpProtocol},
			{Name: "OTEL_SERVICE_NAME", Value: serviceName},
			{Name: "OTEL_RESOURCE_ATTRIBUTES", Value: "k8s.namespace.name=$(POD_NAMESPACE),k8s.pod.name=$(POD_NAME)"},
			{Name: "OTEL_LOGS_EXPORTER", Value: "none"},
			{Name: "OTEL_METRICS_EXPORTER", Value: "none"},
			{Name: "OTEL_TRACES_EXPORTER", Value: "otlp"},
		}

		if jtoIdx >= 0 {
			merged := strings.TrimSpace(c.Env[jtoIdx].Value + " " + agentOpt)
			ops = append(ops, patchOp{
				Op:    "replace",
				Path:  containerPath(idx, "/env/"+itoa(jtoIdx)+"/value"),
				Value: merged,
			})
		} else {
			envs = append([]envVar{{Name: "JAVA_TOOL_OPTIONS", Value: agentOpt}}, envs...)
		}

		if c.Env == nil || len(c.Env) == 0 {
			ops = append(ops, patchOp{
				Op:    "add",
				Path:  containerPath(idx, "/env"),
				Value: envs,
			})
		} else {
			for _, e := range envs {
				ops = append(ops, patchOp{
					Op:    "add",
					Path:  containerPath(idx, "/env/-"),
					Value: e,
				})
			}
		}
	}

	return ops
}

// fieldRef monta um envVar.ValueFrom apontando pro downward API.
func fieldRef(path string) *struct {
	FieldRef *struct {
		FieldPath string `json:"fieldPath"`
	} `json:"fieldRef,omitempty"`
} {
	return &struct {
		FieldRef *struct {
			FieldPath string `json:"fieldPath"`
		} `json:"fieldRef,omitempty"`
	}{FieldRef: &struct {
		FieldPath string `json:"fieldPath"`
	}{FieldPath: path}}
}

func containerPath(idx int, subpath string) string {
	return "/spec/containers/" + itoa(idx) + subpath
}

// itoa minimalista — evita import strconv pro caminho hot.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// workloadOf deriva o nome do workload (Deployment/StatefulSet/DaemonSet) a
// partir do nome do pod. MESMA heurística do scraper quarkus e do frontend
// (lib/workload.ts):
//
//	backend-7959f7697-z6psv → backend   (Deployment: -<rsHash>-<podHash>)
//	postgres-0              → postgres   (StatefulSet: -<ordinal>)
//
// Idempotente pra nomes que já são workload.
func workloadOf(pod string) string {
	if pod == "" {
		return pod
	}
	parts := strings.Split(pod, "-")
	if len(parts) < 2 {
		return pod
	}
	last := parts[len(parts)-1]
	if !isPodSuffix(last) && !isAllDigits(last) {
		return pod
	}
	end := len(parts) - 1
	if end >= 2 && isReplicaSetHash(parts[end-1]) {
		end--
	}
	return strings.Join(parts[:end], "-")
}

func isAlnumLower(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isPodSuffix(s string) bool { return len(s) == 5 && isAlnumLower(s) }

func isReplicaSetHash(s string) bool {
	if len(s) < 8 || len(s) > 10 || !isAlnumLower(s) {
		return false
	}
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}
