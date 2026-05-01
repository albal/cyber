{{- define "cyberscan.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cyberscan.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "cyberscan.image" -}}
{{- $r := .Values.global.image.registry -}}
{{- $repo := .Values.global.image.repository -}}
{{- $tag := .Values.global.image.tag -}}
{{- printf "%s/%s/%s:%s" $r $repo .name $tag -}}
{{- end -}}

{{- define "cyberscan.dbUrl" -}}
postgresql+psycopg://{{ .Values.postgresql.auth.username }}:{{ .Values.postgresql.auth.password }}@{{ .Release.Name }}-postgresql:5432/{{ .Values.postgresql.auth.database }}
{{- end -}}

{{- define "cyberscan.redisUrl" -}}
redis://{{ .Release.Name }}-redis-master:6379/0
{{- end -}}
