{{/* Common name + labels */}}
{{- define "aegis.fullname" -}}
{{- printf "%s-%s" .Release.Name "aegis" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aegis.labels" -}}
app.kubernetes.io/part-of: aegis
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/* Fully-qualified image ref (honors global.imageRegistry) */}}
{{- define "aegis.image" -}}
{{- $registry := .root.Values.global.imageRegistry -}}
{{- $tag := .root.Values.image.tag -}}
{{- if $registry -}}
{{ $registry }}/{{ .repo }}:{{ $tag }}
{{- else -}}
{{ .repo }}:{{ $tag }}
{{- end -}}
{{- end -}}

{{/* The Secret name in use (existing or chart-created) */}}
{{- define "aegis.secretName" -}}
{{- if .Values.secrets.create -}}{{ include "aegis.fullname" . }}-secrets{{- else -}}{{ .Values.secrets.existingSecret }}{{- end -}}
{{- end -}}

{{/* Shared env for API + orchestrator (DB/Redis/config/secrets) */}}
{{- define "aegis.commonEnv" -}}
- name: ENVIRONMENT
  value: {{ .Values.config.environment | quote }}
- name: LOG_LEVEL
  value: {{ .Values.config.logLevel | quote }}
- name: REDIS_ADDR
  value: "{{ include "aegis.fullname" . }}-redis:6379"
- name: DATABASE_URL
  value: "postgres://aegis:$(POSTGRES_PASSWORD)@{{ include "aegis.fullname" . }}-postgres:5432/aegis?sslmode=disable"
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef: { name: {{ include "aegis.secretName" . }}, key: POSTGRES_PASSWORD }
- name: JWT_ACCESS_SECRET
  valueFrom:
    secretKeyRef: { name: {{ include "aegis.secretName" . }}, key: JWT_ACCESS_SECRET }
- name: JWT_REFRESH_SECRET
  valueFrom:
    secretKeyRef: { name: {{ include "aegis.secretName" . }}, key: JWT_REFRESH_SECRET }
- name: TOKEN_ENCRYPTION_KEY
  valueFrom:
    secretKeyRef: { name: {{ include "aegis.secretName" . }}, key: TOKEN_ENCRYPTION_KEY }
{{- end -}}
