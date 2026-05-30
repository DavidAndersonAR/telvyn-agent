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
