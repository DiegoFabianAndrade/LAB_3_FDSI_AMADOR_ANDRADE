$port = 8085
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

function Serve-StaticFile($response, $relativeFilePath, $contentType) {
    $repoRoot = (Get-Item $PSScriptRoot).Parent.FullName
    $fullPath = Join-Path $repoRoot $relativeFilePath
    if (Test-Path $fullPath) {
        $content = Get-Content $fullPath -Raw -Encoding UTF8
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
        $response.ContentType = "$contentType; charset=utf-8"
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.Close()
        return $true
    }
    return $false
}

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
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MuvAutomation Lab - Panel de Presentaci&oacute;n Red/Blue Team</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #151c2c;
      --accent-blue: #38bdf8;
      --accent-red: #f87171;
      --accent-green: #34d399;
      --text: #f1f5f9;
      --muted: #94a3b8;
      --border: #232e47;
    }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 2rem; }
    .container { max-width: 1000px; margin: auto; }
    .header { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 1.8rem; margin-bottom: 1.5rem; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }
    h1 { color: var(--accent-blue); margin: 0 0 0.5rem 0; font-size: 1.8rem; }
    p.subtitle { color: var(--muted); margin: 0 0 1rem 0; font-size: 0.95rem; }
    .badges { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem; }
    .badge { padding: 0.3rem 0.7rem; border-radius: 6px; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }
    .badge-env { background: #0284c7; color: white; }
    .badge-blue { background: #1d4ed8; color: white; }
    .badge-red { background: #b91c1c; color: white; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.2rem; }
    .section-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 1.3rem; }
    .section-card h2 { font-size: 1.15rem; margin-top: 0; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
    .section-card h2.blue-title { color: var(--accent-blue); }
    .section-card h2.red-title { color: var(--accent-red); }
    .section-card h2.green-title { color: var(--accent-green); }
    ul { list-style: none; padding: 0; margin: 0; }
    ul li { margin-bottom: 0.7rem; font-size: 0.92rem; }
    a { color: var(--accent-blue); text-decoration: none; font-weight: 500; transition: color 0.2s; }
    a:hover { color: #7dd3fc; text-decoration: underline; }
    .desc { color: var(--muted); font-size: 0.8rem; display: block; margin-top: 0.15rem; }
    pre { background: #070a11; padding: 1rem; border-radius: 8px; border: 1px solid #1a2336; overflow-x: auto; font-size: 0.85rem; color: #a7f3d0; margin-top: 1rem; }
    footer { text-align: center; margin-top: 2rem; color: var(--muted); font-size: 0.85rem; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>MuvAutomation Asset Portal & Incident Hub</h1>
      <p class="subtitle">Laboratorio 3 - Aplicaci&oacute;n Web P&uacute;blica por HTTP: Construir, Atacar, Detectar, Corregir y Verificar</p>
      <div class="badges">
        <span class="badge badge-env">Entorno: LAB3 HTTP</span>
        <span class="badge badge-blue">Caso: CrowdStrike Falcon (Opci&oacute;n 1)</span>
        <span class="badge badge-red">Red / Blue Team Ready</span>
      </div>
      <p style="margin: 0; font-size: 0.9rem; color: #cbd5e1;">Panel centralizado local para la exposici&oacute;n interactiva de evidencias, prototipo de API y documentaci&oacute;n del laboratorio.</p>
    </div>

    <div class="grid">
      <!-- Card 1: Endpoints Prototipo -->
      <div class="section-card">
        <h2 class="blue-title">[PROTOTIPO] API CrowdStrike</h2>
        <ul>
          <li>
            <a href="/public-inventory.txt" target="_blank">Inventario P&uacute;blico (/public-inventory.txt)</a>
            <span class="desc">Topolog&iacute;a de activos expuestos (WEB-LAB-01, API-LAB-01, DB-LAB-01).</span>
          </li>
          <li>
            <a href="/api/v1/alerts" target="_blank">API Alertas Falcon (/api/v1/alerts)</a>
            <span class="desc">Consulta JSON de incidentes y clasificaci&oacute;n de triaje.</span>
          </li>
          <li>
            <a href="/api/v1/actions" target="_blank">Historial de Acciones (/api/v1/actions)</a>
            <span class="desc">Registro de respuestas automatizadas y acciones defensivas.</span>
          </li>
        </ul>
      </div>

      <!-- Card 2: Red Team Evidencias -->
      <div class="section-card">
        <h2 class="red-title">[RED TEAM] Evidencias (Fase C)</h2>
        <ul>
          <li>
            <a href="/evidence/red/start.txt" target="_blank">Marca de Tiempo de Inicio (/start.txt)</a>
            <span class="desc">Timestamp UTC de inicio de pruebas ofensivas y variables.</span>
          </li>
          <li>
            <a href="/evidence/red/nmap_port80.nmap" target="_blank">Escaneo de Puertos (/nmap_port80.nmap)</a>
            <span class="desc">Resultado de Nmap identificando Nginx 1.18.0 (Ubuntu).</span>
          </li>
          <li>
            <a href="/evidence/red/curl_headers.txt" target="_blank">Fuga de Cabeceras (/curl_headers.txt)</a>
            <span class="desc">Peticiones curl confirmando ausencia de security headers.</span>
          </li>
          <li>
            <a href="/reports/zap-passive/zap-passive-report.html" target="_blank">Reporte OWASP ZAP (/zap-passive-report.html)</a>
            <span class="desc">An&aacute;lisis pasivo de vulnerabilidades expuestas.</span>
          </li>
        </ul>
      </div>

      <!-- Card 3: Blue Team Evidencias & Hardening -->
      <div class="section-card">
        <h2 class="green-title">[BLUE TEAM] Evidencias & Hardening</h2>
        <ul>
          <li>
            <a href="/evidence/blue/access.log" target="_blank">Telemetr&iacute;a Nginx (/access.log)</a>
            <span class="desc">Logs de acceso correlacionando IPs, r&aacute;fagas y User-Agents.</span>
          </li>
          <li>
            <a href="/evidence/blue/detection_rule.py" target="_blank">Regla de Detecci&oacute;n (/detection_rule.py)</a>
            <span class="desc">Script Python de detecci&oacute;n de r&aacute;fagas 404 (5 o m&aacute;s en 5 min).</span>
          </li>
          <li>
            <a href="/nginx/muvautomation-after.conf" target="_blank">Config Nginx Hardened (/muvautomation-after.conf)</a>
            <span class="desc">Directivas server_tokens off y cabeceras de seguridad.</span>
          </li>
          <li>
            <a href="/evidence/retest/headers_after.txt" target="_blank">Retest de Seguridad (/headers_after.txt)</a>
            <span class="desc">Verificaci&oacute;n de mitigaci&oacute;n y denegaci&oacute;n de rutas /.git.</span>
          </li>
        </ul>
      </div>

      <!-- Card 4: Modelado & Documentación -->
      <div class="section-card">
        <h2 class="blue-title">[DOCUMENTOS] Modelado & Informes</h2>
        <ul>
          <li>
            <a href="/diagrams/architecture-dfd.md" target="_blank">Arquitectura & DFD (/architecture-dfd.md)</a>
            <span class="desc">Diagrama de flujo de datos y 2 Fronteras de Confianza.</span>
          </li>
          <li>
            <a href="/diagrams/stride-table.md" target="_blank">Matriz STRIDE (/stride-table.md)</a>
            <span class="desc">4 Hip&oacute;tesis de ataque obligatorias (H1-H4).</span>
          </li>
          <li>
            <a href="/risk-register.md" target="_blank">Registro de Riesgos (/risk-register.md)</a>
            <span class="desc">Matriz de estado de riesgos (Corregido/Lab 4).</span>
          </li>
          <li>
            <a href="/README.md" target="_blank">Informe Completo (/README.md)</a>
            <span class="desc">Preguntas de an&aacute;lisis y reflexi&oacute;n individual.</span>
          </li>
        </ul>
      </div>
    </div>

    <div style="margin-top: 1.5rem;">
      <h3 style="color: var(--accent-blue); font-size: 1.1rem; margin-bottom: 0.5rem;">Consulta de Agregados CrowdStrike Falcon (API Endpoint):</h3>
      <pre>POST /api/v1/alerts/postaggregates
Headers: Content-Type: application/json

Payload de consulta:
{
  "filter": "status:'new'+severity:'High'",
  "group_by": "agent_id"
}</pre>
    </div>

    <footer>
      Laboratorio 3 - FDSI 2026 | Integrantes: Felipe Amador Gonz&aacute;lez & Diego Fabi&aacute;n Andrade Dur&aacute;n
    </footer>
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

    # Rutas estáticas de evidencias
    if ($path -eq "/public-inventory.txt") { 
        if (Serve-StaticFile $response "public-inventory.txt" "text/plain") { continue }
        if (Serve-StaticFile $response "app\public-inventory.txt" "text/plain") { continue }
    }
    if ($path -eq "/evidence/red/start.txt") { if (Serve-StaticFile $response "evidence\red\start.txt" "text/plain") { continue } }
    if ($path -eq "/evidence/red/nmap_port80.nmap") { if (Serve-StaticFile $response "evidence\red\nmap_port80.nmap" "text/plain") { continue } }
    if ($path -eq "/evidence/red/curl_home.txt") { if (Serve-StaticFile $response "evidence\red\curl_home.txt" "text/plain") { continue } }
    if ($path -eq "/evidence/red/curl_headers.txt") { if (Serve-StaticFile $response "evidence\red\curl_headers.txt" "text/plain") { continue } }
    if ($path -eq "/reports/zap-passive/zap-passive-report.html") { if (Serve-StaticFile $response "reports\zap-passive\zap-passive-report.html" "text/html") { continue } }
    if ($path -eq "/reports/zap-passive/zap-passive-report.md") { if (Serve-StaticFile $response "reports\zap-passive\zap-passive-report.md" "text/plain") { continue } }
    if ($path -eq "/evidence/blue/access.log") { if (Serve-StaticFile $response "evidence\blue\access.log" "text/plain") { continue } }
    if ($path -eq "/evidence/blue/error.log") { if (Serve-StaticFile $response "evidence\blue\error.log" "text/plain") { continue } }
    if ($path -eq "/evidence/blue/detection_rule.py") { if (Serve-StaticFile $response "evidence\blue\detection_rule.py" "text/plain") { continue } }
    if ($path -eq "/evidence/retest/nmap_port80.nmap") { if (Serve-StaticFile $response "evidence\retest\nmap_port80.nmap" "text/plain") { continue } }
    if ($path -eq "/evidence/retest/headers_after.txt") { if (Serve-StaticFile $response "evidence\retest\headers_after.txt" "text/plain") { continue } }
    if ($path -eq "/evidence/retest/hidden_path.txt") { if (Serve-StaticFile $response "evidence\retest\hidden_path.txt" "text/plain") { continue } }
    if ($path -eq "/nginx/muvautomation-before.conf") { if (Serve-StaticFile $response "nginx\muvautomation-before.conf" "text/plain") { continue } }
    if ($path -eq "/nginx/muvautomation-after.conf") { if (Serve-StaticFile $response "nginx\muvautomation-after.conf" "text/plain") { continue } }
    if ($path -eq "/diagrams/architecture-dfd.md") { if (Serve-StaticFile $response "diagrams\architecture-dfd.md" "text/plain") { continue } }
    if ($path -eq "/diagrams/stride-table.md") { if (Serve-StaticFile $response "diagrams\stride-table.md" "text/plain") { continue } }
    if ($path -eq "/risk-register.md") { if (Serve-StaticFile $response "risk-register.md" "text/plain") { continue } }
    if ($path -eq "/README.md") { if (Serve-StaticFile $response "README.md" "text/plain") { continue } }

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
  "meta": { "status": 200, "timestamp": "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')" },
  "resources": [
    { "label": "Distribucion por Severidad", "buckets": [ { "count": 1, "value": "High" }, { "count": 1, "value": "Medium" } ] },
    { "label": "Activos Mas Afectados", "buckets": [ { "count": 1, "value": "WEB-LAB-01" }, { "count": 1, "value": "API-LAB-01" } ] }
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
