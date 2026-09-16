/**
 * ============================================================================
 * Módulo de Automatización de Incidentes - CrowdStrike Falcon Hub
 * Proyecto: FDSI 2026 - Laboratorio 3 (HTTP Red/Blue Team)
 * Descripción: Prototipo de procesamiento y clasificación de alertas de seguridad
 * ============================================================================
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8080;

// Base de datos ficticia de alertas de CrowdStrike Falcon (En memoria)
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

// Registro de acciones ejecutadas
const actionLogs = [];

const requestHandler = (req, res) => {
  res.setHeader('X-Lab-Environment', 'LAB3-HTTP-UNAUTHENTICATED');
  res.setHeader('X-Falcon-Mock-Engine', 'Active');

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  console.log(`[REGISTRO] ${new Date().toISOString()} | ${req.method} ${pathname} | User-Agent: ${req.headers['user-agent'] || 'Desconocido'}`);

  // Ruta 1: Portal de activos público
  if (req.method === 'GET' && pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>MuvAutomation Lab - CrowdStrike Incident Hub</title>
  <style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; max-width: 800px; margin: auto; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
    h1 { color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 0.5rem; }
    .badge { display: inline-block; background: #0284c7; color: white; padding: 0.2rem 0.6rem; border-radius: 4px; font-weight: bold; font-size: 0.85rem; }
    a { color: #38bdf8; text-decoration: none; font-weight: 500; }
    a:hover { text-decoration: underline; }
    pre { background: #090d16; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.9rem; color: #a7f3d0; }
  </style>
</head>
<body>
  <div class="card">
    <h1>MuvAutomation Asset Portal & Incident Automation</h1>
    <p><span class="badge">Entorno: LAB</span> <span class="badge">Propietario: Blue Team</span></p>
    <p>Bienvenido al prototipo de automatización de incidentes de <strong>CrowdStrike Falcon</strong> para el Laboratorio 3 HTTP.</p>
    
    <h3>Recursos Disponibles:</h3>
    <ul>
      <li><a href="/public-inventory.txt">Inventario público de demostración</a></li>
      <li><a href="/api/v1/alerts">API de Alertas CrowdStrike Falcon (JSON)</a></li>
      <li><a href="/api/v1/actions">Historial de Acciones de Triaje (JSON)</a></li>
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
</html>`);
  }

  // Ruta 2: Archivo de inventario público
  if (req.method === 'GET' && pathname === '/public-inventory.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end(`=======================================================
MuvAutomation - Demostración de Inventario de Activos
=======================================================
ID-Activo     Nombre-Host     Segmento-IP   Rol
WEB-LAB-01    web.lab.local   192.168.56.10 Servidor Nginx / Incident Hub
API-LAB-01    api.lab.local   192.168.56.11 API CrowdStrike Falcon Mock
DB-LAB-01     db.lab.local    192.168.56.12 Base de Datos de Eventos
=======================================================
Aviso: Expuesto mediante HTTP sin autenticación para evaluación base.
`);
  }

  // Ruta 3: API de Alertas CrowdStrike Falcon
  if (req.method === 'GET' && pathname === '/api/v1/alerts') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
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

  // Ruta 4: Endpoint de agregados (POST /api/v1/alerts/postaggregates)
  if (req.method === 'POST' && pathname === '/api/v1/alerts/postaggregates') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      let parsedBody = {};
      try {
        parsedBody = body ? JSON.parse(body) : {};
      } catch (e) {
        parsedBody = { raw: body };
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        meta: {
          status: 200,
          filtro_solicitado: parsedBody.filter || "ninguno",
          timestamp: new Date().toISOString()
        },
        resources: [
          {
            label: "Distribución por Severidad",
            buckets: [
              { count: alertStore.filter(a => a.severity === 'High').length, value: "High" },
              { count: alertStore.filter(a => a.severity === 'Medium').length, value: "Medium" }
            ]
          },
          {
            label: "Activos Más Afectados",
            buckets: [
              { count: 1, value: "WEB-LAB-01" },
              { count: 1, value: "API-LAB-01" }
            ]
          }
        ]
      }, null, 2));
    });
    return;
  }

  // Ruta 5: Registro de escalamiento y triaje (POST /api/v1/alerts/escalate)
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

      res.writeHead(201, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        status: "success",
        message: "Acción de respuesta registrada correctamente en el prototipo Falcon.",
        action: actionRecord
      }, null, 2));
    });
    return;
  }

  // Ruta 6: Historial de acciones (GET /api/v1/actions)
  if (req.method === 'GET' && pathname === '/api/v1/actions') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      meta: { total_actions: actionLogs.length },
      actions: actionLogs
    }, null, 2));
  }

  // Manejador 404
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    error: "404 Not Found",
    path: pathname,
    message: "Endpoint no encontrado en el prototipo CrowdStrike Incident Hub."
  }));
};

const server = http.createServer(requestHandler);

server.listen(PORT, () => {
  console.log(`===========================================================`);
  console.log(`Servidor CrowdStrike Incident Hub en ejecución`);
  console.log(`URL: http://localhost:${PORT}/`);
  console.log(`Entorno: HTTP sin autenticación (FDSI LAB 3)`);
  console.log(`===========================================================`);
});
