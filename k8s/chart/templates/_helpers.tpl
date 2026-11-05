{{/*
On-prem portability helpers. Every resource is named by "trufflehog.fullname",
which is .Values.fullnameOverride when set and the release name otherwise, so
existing installs (fullnameOverride unset) render exactly as before while an
umbrella chart can give each subchart a static, collision-free name.
*/}}
{{- define "trufflehog.fullname" -}}
{{- default .Release.Name .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Container image reference: [registry/]repository:tag. global.imageRegistry
(umbrella-wide) wins over image.registry; with neither set the reference is
repository:tag, unchanged from before.
*/}}
{{- define "trufflehog.image" -}}
{{- $reg := (.Values.global).imageRegistry | default .Values.image.registry -}}
{{- if $reg }}{{ $reg }}/{{ end }}{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end -}}

{{/*
Name of the Secret mounted via envFrom. Precedence:
externalSecret (ESO target <fullname>-secrets, unchanged) > existingSecret >
secretData (plain Secret rendered by secret.yaml as <fullname>-secrets).
*/}}
{{- define "trufflehog.secretName" -}}
{{- if .Values.externalSecret.enabled -}}
{{- printf "%s-secrets" (include "trufflehog.fullname" .) -}}
{{- else -}}
{{- .Values.existingSecret | default (printf "%s-secrets" (include "trufflehog.fullname" .)) -}}
{{- end -}}
{{- end -}}

{{/*
Emits "true" when some env Secret source is configured (externalSecret,
secretData or existingSecret), empty otherwise. Use as:
  {{- if include "trufflehog.hasEnvSecret" . }}
*/}}
{{- define "trufflehog.hasEnvSecret" -}}
{{- if or .Values.externalSecret.enabled .Values.secretData .Values.existingSecret -}}
true
{{- end -}}
{{- end -}}
