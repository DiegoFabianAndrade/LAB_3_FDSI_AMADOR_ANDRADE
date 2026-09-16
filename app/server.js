const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8080;

const alertStore = [
  {
    id: "inc_cs_9001",
    timestamp: "2026-09-16T14:20:00Z",
    composite_id: "det_falcon_881",
    displayName: "Escaneo de puertos HTTP y reconocimiento de servicio",
    severity: "High",
    status: "new",
    assigned_to: "unassigned",
    agent_id: "WEB-LAB-01",
    tactic: "Reconnaissance",
    technique: "Active Scanning (T1595)",
    description: "Múltiples peticiones HTTP 404 provenientes de un host explorando endpoints públicos."
  },
  {
    id: "inc_cs_9002",
    timestamp: "2026-09-16T14:35:12Z",
    composite_id: "det_falcon_882",
    displayName: "Acceso no cifrado a inventario público",
    severity: "Medium",
    status: "in_progress",
    assigned_to: "soc_analyst_1",
    agent_id: "API-LAB-01",
    tactic: "Discovery",
    technique: "Software Discovery (T1518)",
    description: "Acceso a public-inventory.txt expone topología de activos a través de HTTP."
  }
];

const actionLogs = [];

const serveStaticFile = (res, relativeFilePath, contentType) => {
  const fullPath = path.join(__dirname, '..', relativeFilePath);
  if (fs.existsSync(fullPath)) {
    res.writeHead(200, { 'Content-Type': `${contentType}; charset=utf-8` });
    return res.end(fs.readFileSync(fullPath, 'utf-8'));
  }
  res.writeHead(404, { 'Content-Type': 'application/json' });
  return res.end(JSON.stringify({ error: "Archivo no encontrado en el servidor local" }));
};

const requestHandler = (req, res) => {
  res.setHeader('X-Lab-Environment', 'LAB3-HTTP-UNAUTHENTICATED');
  res.setHeader('X-Falcon-Mock-Engine', 'Active');

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  console.log(`[REGISTRO] ${new Date().toISOString()} | ${req.method} ${pathname} | User-Agent: ${req.headers['user-agent'] || 'Desconocido'}`);

  if (req.method === 'GET' && pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!doctype html>
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
            <a href="/evidence/blue/captura_wireshark_real.png" target="_blank">Captura de Evidencia Wireshark (/captura_wireshark_real.png)</a>
            <span class="desc">Captura de pantalla de inspecci&oacute;n de paquetes HTTP en claro.</span>
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
</html>`);
  }

  if (req.method === 'GET' && pathname === '/public-inventory.txt') return serveStaticFile(res, 'app/public-inventory.txt', 'text/plain');
  if (req.method === 'GET' && pathname === '/evidence/red/start.txt') return serveStaticFile(res, 'evidence/red/start.txt', 'text/plain');
  if (req.method === 'GET' && pathname === '/evidence/red/nmap_port80.nmap') return serveStaticFile(res, 'evidence/red/nmap_port80.nmap', 'text/plain');
  if (req.method === 'GET' && pathname === '/evidence/red/curl_home.txt') return serveStaticFile(res, 'evidence/red/curl_home.txt', 'text/plain');
  if (req.method === 'GET' && pathname === '/evidence/red/curl_headers.txt') return serveStaticFile(res, 'evidence/red/curl_headers.txt', 'text/plain');
  if (req.method === 'GET' && pathname === '/reports/zap-passive/zap-passive-report.html') return serveStaticFile(res, 'reports/zap-passive/zap-passive-report.html', 'text/html');
  if (req.method === 'GET' && pathname === '/reports/zap-passive/zap-passive-report.md') return serveStaticFile(res, 'reports/zap-passive/zap-passive-report.md', 'text/plain');
  if (req.method === 'GET' && pathname === '/evidence/blue/access.log') return serveStaticFile(res, 'evidence/blue/access.log', 'text/plain');
  if (req.method === 'GET' && pathname === '/evidence/blue/error.log') return serveStaticFile(res, 'evidence/blue/error.log', 'text/plain');
  if (req.method === 'GET' && pathname === '/evidence/blue/detection_rule.py') return serveStaticFile(res, 'evidence/blue/detection_rule.py', 'text/plain');
  if (req.method === 'GET' && pathname === '/evidence/blue/captura_wireshark_real.png') return serveStaticFile(res, 'evidence/blue/captura_wireshark_real.png', 'image/png');
  if (req.method === 'GET' && pathname === '/evidence/retest/nmap_port80.nmap') return serveStaticFile(res, 'evidence/retest/nmap_port80.nmap', 'text/plain');
  if (req.method === 'GET' && pathname === '/evidence/retest/headers_after.txt') return serveStaticFile(res, 'evidence/retest/headers_after.txt', 'text/plain');
  if (req.method === 'GET' && pathname === '/evidence/retest/hidden_path.txt') return serveStaticFile(res, 'evidence/retest/hidden_path.txt', 'text/plain');
  if (req.method === 'GET' && pathname === '/nginx/muvautomation-before.conf') return serveStaticFile(res, 'nginx/muvautomation-before.conf', 'text/plain');
  if (req.method === 'GET' && pathname === '/nginx/muvautomation-after.conf') return serveStaticFile(res, 'nginx/muvautomation-after.conf', 'text/plain');
  if (req.method === 'GET' && pathname === '/diagrams/architecture-dfd.md') return serveStaticFile(res, 'diagrams/architecture-dfd.md', 'text/plain');
  if (req.method === 'GET' && pathname === '/diagrams/stride-table.md') return serveStaticFile(res, 'diagrams/stride-table.md', 'text/plain');
  if (req.method === 'GET' && pathname === '/risk-register.md') return serveStaticFile(res, 'risk-register.md', 'text/plain');
  if (req.method === 'GET' && pathname === '/README.md') return serveStaticFile(res, 'README.md', 'text/plain');

  if (req.method === 'GET' && pathname === '/api/v1/alerts') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    return res.end(JSON.stringify({
      meta: {
        query_time: new Date().toISOString(),
        total_alerts: alertStore.length,
        motor_triaje: "Procesador de Alertas CrowdStrike Falcon v1.0",
        trace_id: `trace_${Math.random().toString(36).substring(2, 9)}`
      },
      resources: alertStore
    }, null, 2));
  }

  if (req.method === 'POST' && pathname === '/api/v1/alerts/postaggregates') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      let parsedBody = {};
      try { parsedBody = body ? JSON.parse(body) : {}; } catch (e) { parsedBody = { raw: body }; }

      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({
        meta: { status: 200, filtro_solicitado: parsedBody.filter || "ninguno", timestamp: new Date().toISOString() },
        resources: [
          { label: "Distribución por Severidad", buckets: [{ count: alertStore.filter(a => a.severity === 'High').length, value: "High" }, { count: alertStore.filter(a => a.severity === 'Medium').length, value: "Medium" }] },
          { label: "Activos Más Afectados", buckets: [{ count: 1, value: "WEB-LAB-01" }, { count: 1, value: "API-LAB-01" }] }
        ]
      }, null, 2));
    });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/v1/alerts/escalate') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      let payload = {};
      try { payload = JSON.parse(body); } catch (e) {}

      const actionRecord = {
        action_id: `act_${Date.now()}`,
        alert_id: payload.alert_id || "inc_cs_9001",
        action_type: payload.action_type || "CONTAINMENT_RECOMMENDED",
        executed_by: payload.executed_by || "BlueTeam-SOAR-Bot",
        timestamp: new Date().toISOString(),
        details: payload.details || "Regla de triaje automatizado detectó escaneo HTTP."
      };

      actionLogs.push(actionRecord);

      res.writeHead(201, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({ status: "success", message: "Acción de respuesta registrada correctamente en el prototipo Falcon.", action: actionRecord }, null, 2));
    });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/v1/actions') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    return res.end(JSON.stringify({ meta: { total_actions: actionLogs.length }, actions: actionLogs }, null, 2));
  }

  res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ error: "404 Not Found", path: pathname, message: "Endpoint no encontrado en el prototipo CrowdStrike Incident Hub." }));
};

const server = http.createServer(requestHandler);

server.listen(PORT, () => {
  console.log(`Servidor CrowdStrike Incident Hub en ejecución en puerto ${PORT}`);
});
