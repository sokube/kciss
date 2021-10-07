{{/*
Expand the name of the chart.
*/}}
{{- define "kciss.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kciss.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create controller name and version as used by the chart label.
*/}}
{{- define "kciss.kciss.fullname" -}}
{{- printf "%s-%s" (include "kciss.fullname" .) "kciss" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create controller name and version as used by the chart label.
*/}}
{{- define "kciss.trivy.fullname" -}}
{{- printf "%s-%s" (include "kciss.fullname" .) "trivy" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kciss.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kciss.labels" -}}
helm.sh/chart: {{ include "kciss.chart" . }}
{{ include "kciss.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: kciss
{{- end }}

{{/*
KCISS Common Labels
*/}}
{{- define "kciss.kciss.labels" -}}
{{ include "kciss.labels" . }}
app.kubernetes.io/component: kciss
{{- end }}

{{/*
TRIVY Common Labels
*/}}
{{- define "kciss.trivy.labels" -}}
{{ include "kciss.labels" . }}
app.kubernetes.io/component: trivy
{{- end }}


{{/*
Selector labels
*/}}
{{- define "kciss.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kciss.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
KCISS Selector labels
*/}}
{{- define "kciss.kciss.selectorLabels" -}}
{{ include "kciss.selectorLabels" . }}
app.kubernetes.io/component: kciss
{{- end }}

{{/*
TRIVY Selector labels
*/}}
{{- define "kciss.trivy.selectorLabels" -}}
{{ include "kciss.selectorLabels" . }}
app.kubernetes.io/component: trivy
{{- end }}

{{/*
Create the name of the service account to use for kciss deployment
*/}}
{{- define "kciss.kciss.serviceAccountName" -}}
{{- if .Values.kciss.serviceAccount.create }}
{{- default (include "kciss.kciss.fullname" .) .Values.kciss.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.kciss.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use for trivy deployment
*/}}
{{- define "kciss.trivy.serviceAccountName" -}}
{{- if .Values.trivy.serviceAccount.create }}
{{- default (include "kciss.trivy.fullname" .) .Values.trivy.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.trivy.serviceAccount.name }}
{{- end }}
{{- end }}
