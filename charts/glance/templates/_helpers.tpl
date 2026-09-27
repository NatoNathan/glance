{{- define "glance.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "glance.fullname" -}}
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

{{- define "glance.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "glance.labels" -}}
helm.sh/chart: {{ include "glance.chart" . }}
{{ include "glance.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "glance.selectorLabels" -}}
app.kubernetes.io/name: {{ include "glance.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "glance.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "glance.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "glance.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{/* Name of the ConfigMap holding glance.yml */}}
{{- define "glance.configMapName" -}}
{{- .Values.existingConfigMap | default (include "glance.fullname" .) }}
{{- end }}

{{/* Name of the Secret holding the generated secret-key */}}
{{- define "glance.secretKeySecretName" -}}
{{- .Values.secretKey.existingSecret | default (printf "%s-secret-key" (include "glance.fullname" .)) }}
{{- end }}

{{/*
The rendered glance.yml. The container port is forced to match the chart and, when OIDC is
configured without an explicit session-file, sessions are stored on the data volume since the
config directory is a read-only ConfigMap mount. The config isn't passed through tpl because
widgets such as custom-api use Go template syntax of their own.
*/}}
{{- define "glance.config" -}}
{{- if kindIs "string" .Values.config }}
{{- .Values.config }}
{{- else }}
{{- $config := deepCopy .Values.config }}
{{- $server := get $config "server" | default dict }}
{{- $_ := set $server "port" (int .Values.containerPort) }}
{{- $_ := set $config "server" $server }}
{{- $auth := get $config "auth" | default dict }}
{{- $oidc := get $auth "oidc" }}
{{- if and $oidc (not (hasKey $oidc "session-file")) }}
{{- $_ := set $oidc "session-file" (printf "%s/glance-oidc-sessions.dat" .Values.persistence.mountPath) }}
{{- end }}
{{- toYaml $config }}
{{- end }}
{{- end }}

