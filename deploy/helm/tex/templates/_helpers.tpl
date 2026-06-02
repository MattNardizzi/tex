{{- define "tex.namespace" -}}{{ .Values.namespace }}{{- end -}}
{{- define "tex.labels" -}}
app.kubernetes.io/part-of: tex
app.kubernetes.io/managed-by: helm
{{- end -}}
