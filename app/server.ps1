$port = 8080
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$port/")
$listener.Start()

Write-Host "==========================================================="
Write-Host "Servidor CrowdStrike Incident Hub en ejecucion (PowerShell)"
Write-Host "URL: http://localhost:$port/"
Write-Host "Entorno: HTTP sin autenticacion (FDSI LAB 3)"
Write-Host "Presione Ctrl+C para detener el servidor"
Write-Host "==========================================================="

$alertStoreJson = @'
[
  {
    "id": "inc_cs_9001",
    "timestamp": "2026-09-16T14:20:00Z",
    "composite_id": "det_falcon_881",
    "displayName": "Escaneo de puertos HTTP y reconocimiento de servicio",
    "severity": "High",
    "status": "new",
    "assigned_to": "unassigned",
    "agent_id": "WEB-LAB-01",
    "tactic": "Reconnaissance",
    "technique": "Active Scanning (T1595)",
    "description": "Multiples peticiones HTTP 404 provenientes de un host explorando endpoints publicos."
  },
  {
    "id": "inc_cs_9002",
    "timestamp": "2026-09-16T14:35:12Z",
    "composite_id": "det_falcon_882",
    "displayName": "Acceso no cifrado a inventario publico",
    "severity": "Medium",
    "status": "in_progress",
    "assigned_to": "soc_analyst_1",
    "agent_id": "API-LAB-01",
    "tactic": "Discovery",
    "technique": "Software Discovery (T1518)",
    "description": "Acceso a public-inventory.txt expone topologia de activos a traves de HTTP."
  }
]
'@

while ($listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response

    $response.Headers.Add("X-Lab-Environment", "LAB3-HTTP-UNAUTHENTICATED")
    $response.Headers.Add("X-Falcon-Mock-Engine", "Active-PowerShell")

    $path = $request.Url.AbsolutePath
    $method = $request.HttpMethod
    Write-Host "[REGISTRO] $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ') | $method $path | User-Agent: $($request.UserAgent)"

    if ($method -eq "GET" -and $path -eq "/") {
        $html = @"
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>MuvAutomation Lab - CrowdStrike Incident Hub</title>
  <style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; max-width: 850px; margin: auto; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
    h1 { color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 0.5rem; }
    h3 { color: #38bdf8; margin-top: 1.5rem; border-left: 3px solid #0284c7; padding-left: 0.5rem; }
    .badge { display: inline-block; background: #0284c7; color: white; padding: 0.2rem 0.6rem; border-radius: 4px; font-weight: bold; font-size: 0.85rem; }
    .badge-red { background: #ef4444; }
    .badge-blue { background: #3b82f6; }
    a { color: #38bdf8; text-decoration: none; font-weight: 500; }
    a:hover { text-decoration: underline; }
    pre { background: #090d16; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.9rem; color: #a7f3d0; }
    ul li { margin-bottom: 0.5rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Portal de Activos y Automatizaci&oacute;n de Incidentes</h1>
    <p><span class="badge">Entorno: LAB</span> <span class="badge badge-blue">Propietario: Blue Team</span></p>
    <p>Bienvenido al prototipo de automatizaci&oacute;n de incidentes de <strong>CrowdStrike Falcon</strong> para el Laboratorio 3 HTTP.</p>
    
    <h3>Recursos del Prototipo & API:</h3>
    <ul>
      <li><a href="/public-inventory.txt">Inventario p&uacute;blico de demostraci&oacute;n</a></li>
      <li><a href="/api/v1/alerts">API de Alertas CrowdStrike Falcon (JSON)</a></li>
      <li><a href="/api/v1/actions">Historial de Acciones de Triaje (JSON)</a></li>
    </ul>

    <h3>Evidencias y Hallazgos Red Team & Blue Team:</h3>
    <ul>
      <li><span class="badge badge-red">Red Team</span> <a href="/evidence/red/curl_headers.txt" target="_blank">Reconocimiento HTTP y Fuga de Cabeceras (curl)</a></li>
      <li><span class="badge badge-red">Red Team</span> <a href="/reports/zap-passive/zap-passive-report.html" target="_blank">Reporte de Escaneo Pasivo de Vulnerabilidades (OWASP ZAP)</a></li>
      <li><span class="badge badge-blue">Blue Team</span> <a href="/evidence/retest/headers_after.txt" target="_blank">Verificaci&oacute;n de Hardening de Nginx (Retest)</a></li>
    </ul>

    <h3>Esquema de Agregados CrowdStrike Falcon (Endpoint API):</h3>
    <pre>POST /api/v1/alerts/postaggregates
Headers: Content-Type: application/json

Payload de consulta:
{
  "filter": "status:'new'+severity:'High'",
  "group_by": "agent_id"
}</pre>
  </div>
</body>
</html>
"@
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
        $response.ContentType = "text/html; charset=utf-8"
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.Close()
        continue
    }

    if ($method -eq "GET" -and $path -eq "/public-inventory.txt") {
        $txt = @"
=======================================================
MuvAutomation - Demostracion de Inventario de Activos
=======================================================
ID-Activo     Nombre-Host     Segmento-IP   Rol
WEB-LAB-01    web.lab.local   192.168.56.10 Servidor Nginx / Incident Hub
API-LAB-01    api.lab.local   192.168.56.11 API CrowdStrike Falcon Mock
DB-LAB-01     db.lab.local    192.168.56.12 Base de Datos de Eventos
=======================================================
Aviso: Expuesto mediante HTTP sin autenticacion para evaluacion base.
"@
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($txt)
        $response.ContentType = "text/plain; charset=utf-8"
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.Close()
        continue
    }

    if ($method -eq "GET" -and $path -eq "/evidence/red/curl_headers.txt") {
        $filePath = Join-Path (Get-Item $PSScriptRoot).Parent.FullName "evidence\red\curl_headers.txt"
        if (Test-Path $filePath) {
            $txt = Get-Content $filePath -Raw
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($txt)
            $response.ContentType = "text/plain; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            $response.Close()
            continue
        }
    }

    if ($method -eq "GET" -and $path -eq "/reports/zap-passive/zap-passive-report.html") {
        $filePath = Join-Path (Get-Item $PSScriptRoot).Parent.FullName "reports\zap-passive\zap-passive-report.html"
        if (Test-Path $filePath) {
            $htmlContent = Get-Content $filePath -Raw
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($htmlContent)
            $response.ContentType = "text/html; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            $response.Close()
            continue
        }
    }

    if ($method -eq "GET" -and $path -eq "/evidence/retest/headers_after.txt") {
        $filePath = Join-Path (Get-Item $PSScriptRoot).Parent.FullName "evidence\retest\headers_after.txt"
        if (Test-Path $filePath) {
            $txt = Get-Content $filePath -Raw
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($txt)
            $response.ContentType = "text/plain; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            $response.Close()
            continue
        }
    }

    if ($method -eq "GET" -and $path -eq "/api/v1/alerts") {
        $jsonResp = @"
{
  "meta": {
    "query_time": "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')",
    "total_alerts": 2,
    "motor_triaje": "Procesador de Alertas CrowdStrike Falcon v1.0 [PowerShell]"
  },
  "resources": $alertStoreJson
}
"@
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($jsonResp)
        $response.ContentType = "application/json; charset=utf-8"
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.Close()
        continue
    }

    if ($method -eq "POST" -and $path -eq "/api/v1/alerts/postaggregates") {
        $jsonResp = @"
{
  "meta": {
    "status": 200,
    "timestamp": "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
  },
  "resources": [
    {
      "label": "Distribucion por Severidad",
      "buckets": [
        { "count": 1, "value": "High" },
        { "count": 1, "value": "Medium" }
      ]
    },
    {
      "label": "Activos Mas Afectados",
      "buckets": [
        { "count": 1, "value": "WEB-LAB-01" },
        { "count": 1, "value": "API-LAB-01" }
      ]
    }
  ]
}
"@
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($jsonResp)
        $response.ContentType = "application/json; charset=utf-8"
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.Close()
        continue
    }

    $errJson = '{"error": "404 Not Found", "message": "Endpoint no encontrado en el prototipo CrowdStrike Incident Hub."}'
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($errJson)
    $response.StatusCode = 404
    $response.ContentType = "application/json; charset=utf-8"
    $response.ContentLength64 = $buffer.Length
    $response.OutputStream.Write($buffer, 0, $buffer.Length)
    $response.Close()
}
