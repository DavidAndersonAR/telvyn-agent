// Package sbom — capability de vulnerabilidade de APLICAÇÃO (camada 2/3), no
// estilo Datadog: o agente embute o Trivy (binário ao lado, só geração de SBOM,
// SEM banco de CVE), escaneia as IMAGENS dos containers rodando no nó e manda só
// a LISTA de componentes (CycloneDX achatado) pro gateway. O casamento com o
// catálogo de advisory roda 100% no backend (POST /api/ingest/v1/sbom).
//
// Ligado por toggle (ISPWATCH_SBOM_SCAN=1, via Helm sbomScan.enabled). As imagens
// rodando vêm do kubelet /pods (mesma fonte do carimbo de pod). Dedup por digest
// (imagem muda raro) com TTL — não re-escaneia a mesma imagem a cada ciclo.
package sbom

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Pusher é o subconjunto do IngestExporter que usamos (POST Bearer pro gateway).
type Pusher interface {
	PostRaw(ctx context.Context, signal, contentType string, body []byte) error
}

// Config do scanner. Os campos de kubelet espelham os do pod-resolver do eBPF.
type Config struct {
	HostID            string        // host_id do nó registrado (∈ tenant) — vai no ingest
	KubeletURL        string        // ex: https://localhost:10250
	KubeletTokenFile  string        // token do serviceaccount
	KubeletCAFile     string        // CA (vazio = insecure)
	KubeletInsecure   bool          // pula verificação de cert (k3d/dev)
	TrivyPath         string        // caminho do binário trivy (default "trivy")
	ExtraTrivyArgs    []string      // args extras (configurável sem rebuild)
	ContainerdAddr    string        // CONTAINERD_ADDRESS (socket do containerd)
	ContainerdNS      string        // CONTAINERD_NAMESPACE (k8s.io)
	Interval          time.Duration // intervalo entre varreduras
	RescanTTL         time.Duration // não re-escaneia o mesmo digest dentro deste TTL
	ExcludeNamespaces []string      // namespaces a ignorar (ex: o do próprio agente)
}

// Scanner orquestra: lista imagens → escaneia as novas → manda o SBOM.
type Scanner struct {
	cfg     Config
	pusher  Pusher
	log     *slog.Logger
	lister  *imageLister
	scanned map[string]time.Time // digest → último scan
}

// New monta o scanner. Erra se o lister do kubelet não inicializar.
func New(cfg Config, pusher Pusher, log *slog.Logger) (*Scanner, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.TrivyPath == "" {
		cfg.TrivyPath = "trivy"
	}
	if cfg.ContainerdNS == "" {
		cfg.ContainerdNS = "k8s.io"
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Hour
	}
	if cfg.RescanTTL <= 0 {
		cfg.RescanTTL = 12 * time.Hour
	}
	lister, err := newImageLister(cfg.KubeletURL, cfg.KubeletTokenFile, cfg.KubeletCAFile, cfg.KubeletInsecure)
	if err != nil {
		return nil, fmt.Errorf("sbom: kubelet image lister: %w", err)
	}
	return &Scanner{
		cfg:     cfg,
		pusher:  pusher,
		log:     log.With("component", "sbom-scanner"),
		lister:  lister,
		scanned: map[string]time.Time{},
	}, nil
}

// Run roda a varredura no boot e a cada Interval. Bloqueia até ctx cancelar.
func (s *Scanner) Run(ctx context.Context) {
	s.log.Info("sbom scanner iniciado", "interval", s.cfg.Interval.String(), "trivy", s.cfg.TrivyPath)
	s.scanOnce(ctx)
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.scanOnce(ctx)
		}
	}
}

func (s *Scanner) scanOnce(ctx context.Context) {
	images, err := s.lister.List(ctx)
	if err != nil {
		s.log.Warn("sbom: falha listando imagens do kubelet", "err", err)
		return
	}
	// dedup por digest: escaneia 1x por conteúdo de imagem. Mantém o 1º (ns/pod/svc).
	seen := map[string]RunningImage{}
	for _, img := range images {
		if img.Digest == "" || s.excluded(img.Namespace) {
			continue
		}
		if _, ok := seen[img.Digest]; !ok {
			seen[img.Digest] = img
		}
	}
	now := time.Now()
	scanned, posted := 0, 0
	for digest, img := range seen {
		if last, ok := s.scanned[digest]; ok && now.Sub(last) < s.cfg.RescanTTL {
			continue // já escaneado recentemente
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		comps, err := s.scanImage(ctx, img.Ref)
		s.scanned[digest] = time.Now() // marca mesmo em erro (evita martelar imagem quebrada)
		scanned++
		if err != nil {
			s.log.Warn("sbom: trivy falhou", "image", img.Ref, "err", err)
			continue
		}
		if len(comps) == 0 {
			continue
		}
		if err := s.post(ctx, img, digest, comps); err != nil {
			s.log.Warn("sbom: post falhou", "image", img.Ref, "err", err)
			continue
		}
		posted++
	}
	if scanned > 0 {
		s.log.Info("sbom: varredura concluída", "imagens", len(seen), "escaneadas", scanned, "enviadas", posted)
	}
}

func (s *Scanner) excluded(ns string) bool {
	for _, ex := range s.cfg.ExcludeNamespaces {
		if ns == ex {
			return true
		}
	}
	return false
}

// scanImage roda o trivy (geração de SBOM, sem banco de CVE) e achata o
// CycloneDX na lista que o ingest espera.
func (s *Scanner) scanImage(ctx context.Context, imageRef string) ([]ingestComponent, error) {
	args := []string{"image", "--quiet", "--format", "cyclonedx", "--image-src", "containerd"}
	args = append(args, s.cfg.ExtraTrivyArgs...)
	args = append(args, imageRef)

	cmd := exec.CommandContext(ctx, s.cfg.TrivyPath, args...)
	cmd.Env = append(os.Environ(), "CONTAINERD_NAMESPACE="+s.cfg.ContainerdNS)
	if s.cfg.ContainerdAddr != "" {
		cmd.Env = append(cmd.Env, "CONTAINERD_ADDRESS="+s.cfg.ContainerdAddr)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 240 {
			msg = msg[:240]
		}
		return nil, fmt.Errorf("%w: %s", err, msg)
	}
	return flattenCycloneDX(stdout.Bytes())
}

// post monta o payload do ingest e manda pro gateway. host_id é numérico no
// backend — converte; se não for numérico, descarta (não dá pra atribuir).
func (s *Scanner) post(ctx context.Context, img RunningImage, digest string, comps []ingestComponent) error {
	hostID, err := strconv.ParseInt(strings.TrimSpace(s.cfg.HostID), 10, 64)
	if err != nil {
		return fmt.Errorf("host_id não-numérico %q", s.cfg.HostID)
	}
	payload := ingestPayload{
		HostID:      hostID,
		ImageRef:    img.Ref,
		ImageDigest: digest,
		Namespace:   img.Namespace,
		Service:     img.Service,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Components:  comps,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.pusher.PostRaw(ctx, "sbom", "application/json", body)
}

// ---- payload do ingest (espelha SbomIngestResource) ---------------------

type ingestPayload struct {
	HostID      int64             `json:"host_id"`
	ImageRef    string            `json:"image_ref"`
	ImageDigest string            `json:"image_digest"`
	Namespace   string            `json:"namespace,omitempty"`
	Service     string            `json:"service,omitempty"`
	GeneratedAt string            `json:"generated_at,omitempty"`
	Components  []ingestComponent `json:"components"`
}

type ingestComponent struct {
	Purl    string `json:"purl,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type,omitempty"`
}

// ---- CycloneDX (achatamento) --------------------------------------------

type cdxBOM struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type    string `json:"type"` // library | application | operating-system | …
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl"`
}

// flattenCycloneDX lê o SBOM CycloneDX do Trivy e devolve a lista de componentes
// no shape do ingest. type "operating-system" → "os"; o resto → "library".
func flattenCycloneDX(raw []byte) ([]ingestComponent, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("trivy: SBOM vazio")
	}
	var bom cdxBOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		return nil, fmt.Errorf("trivy: SBOM inválido: %w", err)
	}
	out := make([]ingestComponent, 0, len(bom.Components))
	for _, c := range bom.Components {
		if c.Name == "" || c.Version == "" {
			continue // sem nome/versão não dá pra casar
		}
		t := "library"
		if c.Type == "operating-system" {
			t = "os"
		}
		out = append(out, ingestComponent{
			Purl:    c.Purl,
			Name:    c.Name,
			Version: c.Version,
			Type:    t,
		})
	}
	return out, nil
}

// ---- lister de imagens rodando (kubelet /pods) --------------------------

// RunningImage = uma imagem de container rodando no nó.
type RunningImage struct {
	Ref       string // ex: docker.io/library/nginx:1.21
	Digest    string // sha256:… (do imageID)
	Namespace string
	Pod       string
	Service   string // label tags.datadoghq.com/service, se houver
}

type imageLister struct {
	url    string
	token  string
	client *http.Client
}

func newImageLister(kubeletURL, tokenFile, caFile string, insecure bool) (*imageLister, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: insecure}
	if caFile != "" && !insecure {
		ca, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("ca %s sem PEM", caFile)
		}
		tlsCfg.RootCAs = pool
		tlsCfg.InsecureSkipVerify = false
	}
	token := ""
	if tokenFile != "" {
		if b, err := os.ReadFile(tokenFile); err == nil {
			token = strings.TrimSpace(string(b))
		}
	}
	return &imageLister{
		url:   strings.TrimRight(kubeletURL, "/") + "/pods",
		token: token,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

func (l *imageLister) List(ctx context.Context) ([]RunningImage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.url, nil)
	if err != nil {
		return nil, err
	}
	if l.token != "" {
		req.Header.Set("Authorization", "Bearer "+l.token)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("kubelet /pods status %d: %s", resp.StatusCode, string(body))
	}
	var list kubeletPodList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("decode kubelet /pods: %w", err)
	}
	var out []RunningImage
	for _, p := range list.Items {
		svc := p.Metadata.Labels["tags.datadoghq.com/service"]
		for _, c := range p.Status.ContainerStatuses {
			ref := strings.TrimSpace(c.Image)
			digest := extractDigest(c.ImageID)
			if ref == "" || digest == "" {
				continue
			}
			out = append(out, RunningImage{
				Ref:       ref,
				Digest:    digest,
				Namespace: p.Metadata.Namespace,
				Pod:       p.Metadata.Name,
				Service:   svc,
			})
		}
	}
	return out, nil
}

// extractDigest pega o "sha256:…" do imageID do kubelet. Formatos comuns:
//
//	"docker-pullable://repo@sha256:abc…", "repo@sha256:abc…", "sha256:abc…".
func extractDigest(imageID string) string {
	if i := strings.Index(imageID, "sha256:"); i >= 0 {
		return imageID[i:]
	}
	return ""
}

type kubeletPodList struct {
	Items []struct {
		Metadata struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Labels    map[string]string `json:"labels"`
		} `json:"metadata"`
		Status struct {
			ContainerStatuses []struct {
				Image   string `json:"image"`
				ImageID string `json:"imageID"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}
