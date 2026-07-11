{{/* Chart name and full release name */}}
{{- define "ispwatch-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ispwatch-agent.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "ispwatch-agent.labels" -}}
app.kubernetes.io/name: {{ include "ispwatch-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/component: agent
{{- end -}}

{{- define "ispwatch-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ispwatch-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Cluster Agent (component=cluster-agent) — labels próprias pra não duplicar
     a chave app.kubernetes.io/component do helper .labels (que fixa =agent). */}}
{{- define "ispwatch-agent.clusterLabels" -}}
app.kubernetes.io/name: {{ include "ispwatch-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/component: cluster-agent
{{- end -}}

{{- define "ispwatch-agent.clusterSelectorLabels" -}}
app.kubernetes.io/name: {{ include "ispwatch-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: cluster-agent
{{- end -}}
