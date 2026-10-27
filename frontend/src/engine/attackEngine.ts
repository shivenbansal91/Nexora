/**
 * attackEngine.ts — Pure frontend simulation engine.
 * No React, no DOM, no real network requests.
 * Generates realistic attack chains and timed event sequences.
 */

export type NodeType = 'external_ip' | 'api' | 'user' | 'server' | 'database';

export interface GraphNodeDef {
  id: string;
  type: NodeType;
  label: string;
  sublabel: string;
}

export interface GraphEdgeDef {
  from: string;
  to: string;
}

export interface AttackEvent {
  id: string;
  time: string;
  severity: 'critical' | 'high' | 'medium' | 'info';
  label: string;
  method?: string;
  path?: string;
  ip?: string;
  detail: string;
  delayMs: number;
}

export interface ThreatInfo {
  badge: string;
  badgeColor: string;
  title: string;
  subtitle: string;
  confidence: number;
  relatedEvents: number;
  chain: string;
  firstSeen: string;
}

export interface GeneratedAttack {
  scenarioName: string;
  chainNodes: GraphNodeDef[];
  chainEdges: GraphEdgeDef[];
  events: AttackEvent[];
  threat: ThreatInfo;
  chainId: string;
}

// ── Node Pools ────────────────────────────────────────────────────────────────

const IP_POOL: GraphNodeDef[] = [
  { id: 'ip-1', type: 'external_ip', label: '185.42.91.8',   sublabel: 'AS204915 · RU' },
  { id: 'ip-2', type: 'external_ip', label: '45.138.27.41',  sublabel: 'AS209353 · NL' },
  { id: 'ip-3', type: 'external_ip', label: '103.56.148.22', sublabel: 'AS45753 · CN'  },
  { id: 'ip-4', type: 'external_ip', label: '91.239.244.11', sublabel: 'AS208843 · DE' },
];

const API_POOL: GraphNodeDef[] = [
  { id: 'api-login',   type: 'api', label: '/api/login',         sublabel: 'Auth endpoint'    },
  { id: 'api-search',  type: 'api', label: '/api/users/search',  sublabel: 'User search API'  },
  { id: 'api-export',  type: 'api', label: '/api/admin/export',  sublabel: 'Data export API'  },
  { id: 'api-token',   type: 'api', label: '/api/auth/token',    sublabel: 'Token endpoint'   },
  { id: 'api-jobs',    type: 'api', label: '/api/internal/jobs', sublabel: 'Job scheduler'    },
];

const USER_POOL: GraphNodeDef[] = [
  { id: 'usr-admin',    type: 'user', label: 'admin',        sublabel: 'Admin Account'   },
  { id: 'usr-reporter', type: 'user', label: 'svc_reporter', sublabel: 'Service Account' },
  { id: 'usr-jdoe',    type: 'user', label: 'j.doe',        sublabel: 'Employee'        },
  { id: 'usr-root',    type: 'user', label: 'root',         sublabel: 'System Account'  },
];

const SERVER_POOL: GraphNodeDef[] = [
  { id: 'srv-gw',   type: 'server', label: 'api-gateway',   sublabel: 'Edge Gateway' },
  { id: 'srv-auth', type: 'server', label: 'auth-server',   sublabel: 'Auth Service' },
  { id: 'srv-app',  type: 'server', label: 'app-server-02', sublabel: 'App Tier'     },
];

const DB_POOL: GraphNodeDef[] = [
  { id: 'db-prod',    type: 'database', label: 'db-prod-01', sublabel: 'Customer PII'     },
  { id: 'db-finance', type: 'database', label: 'db-finance',  sublabel: 'Financial Records'},
  { id: 'db-audit',   type: 'database', label: 'db-audit',    sublabel: 'Audit Logs'      },
];

// ── Helpers ──────────────────────────────────────────────────────────────────

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function now(): string {
  return new Date().toLocaleTimeString('en-US', { hour12: false });
}

let chainSeq = Math.floor(Math.random() * 50) + 10;

// ── Scenario Definitions ─────────────────────────────────────────────────────

interface Scenario {
  name: string;
  chainTypes: NodeType[];
  buildEvents(nodes: GraphNodeDef[], chainId: string): AttackEvent[];
  buildThreat(nodes: GraphNodeDef[], chainId: string): ThreatInfo;
}

const SCENARIOS: Scenario[] = [
  {
    name: 'SQL Injection',
    chainTypes: ['external_ip', 'api', 'database'],
    buildEvents(nodes, chainId) {
      const ip  = nodes[0]; const api = nodes[1]; const db = nodes[2];
      const t = now();
      return [
        { id: `ev-a`, time: t, severity: 'medium',   label: 'Suspicious Request',  method: 'POST', path: api.label, ip: ip.label, detail: 'Unusual parameter encoding in body',                       delayMs: 0    },
        { id: `ev-b`, time: t, severity: 'high',     label: 'Anomaly Detected',    method: 'POST', path: api.label, ip: ip.label, detail: 'SQL metacharacter in query string — possible injection',   delayMs: 1400 },
        { id: `ev-c`, time: t, severity: 'critical', label: 'Threat Identified',   method: 'POST', path: api.label, ip: ip.label, detail: `SQL Injection pattern matched · targeting ${db.label}`,   delayMs: 3000 },
        { id: `ev-d`, time: t, severity: 'info',     label: 'Correlation Created', method: '—',   path: chainId,   ip: '—',      detail: `${ip.label} → ${api.label} → ${db.label} linked`,         delayMs: 4500 },
      ];
    },
    buildThreat(nodes, chainId) {
      return { badge: 'POTENTIAL THREAT', badgeColor: 'rose', title: 'Possible SQL Injection', subtitle: nodes[1].label, confidence: 91, relatedEvents: 4, chain: chainId, firstSeen: 'Just now' };
    },
  },
  {
    name: 'Brute Force',
    chainTypes: ['external_ip', 'api', 'user', 'server'],
    buildEvents(nodes, chainId) {
      const ip = nodes[0]; const api = nodes[1]; const user = nodes[2];
      const t = now();
      return [
        { id: `ev-a`, time: t, severity: 'medium',   label: 'Suspicious Request',  method: 'POST', path: api.label, ip: ip.label, detail: `Repeated auth attempts from ${ip.label}`,       delayMs: 0    },
        { id: `ev-b`, time: t, severity: 'high',     label: 'Anomaly Detected',    method: 'POST', path: api.label, ip: ip.label, detail: '120 login failures in 60 seconds — rate spike',  delayMs: 1600 },
        { id: `ev-c`, time: t, severity: 'critical', label: 'Threat Identified',   method: 'POST', path: api.label, ip: ip.label, detail: `Brute force targeting account: ${user.label}`,   delayMs: 3200 },
        { id: `ev-d`, time: t, severity: 'info',     label: 'Correlation Created', method: '—',   path: chainId,   ip: '—',      detail: `Account lockout triggered for ${user.label}`,     delayMs: 4800 },
      ];
    },
    buildThreat(nodes, chainId) {
      return { badge: 'BRUTE FORCE', badgeColor: 'amber', title: 'Credential Brute Force', subtitle: nodes[1].label, confidence: 97, relatedEvents: 12, chain: chainId, firstSeen: 'Just now' };
    },
  },
  {
    name: 'Data Exfiltration',
    chainTypes: ['external_ip', 'api', 'user', 'database'],
    buildEvents(nodes, chainId) {
      const ip = nodes[0]; const api = nodes[1]; const db = nodes[3];
      const t = now();
      return [
        { id: `ev-a`, time: t, severity: 'medium',   label: 'Suspicious Request',  method: 'GET', path: api.label, ip: ip.label, detail: 'Unusual bulk data request pattern',                  delayMs: 0    },
        { id: `ev-b`, time: t, severity: 'high',     label: 'Anomaly Detected',    method: 'GET', path: api.label, ip: ip.label, detail: `Large response payload → ${ip.label}`,               delayMs: 1800 },
        { id: `ev-c`, time: t, severity: 'critical', label: 'Threat Identified',   method: 'GET', path: api.label, ip: ip.label, detail: `Data exfil attempt from ${db.label}`,                delayMs: 3500 },
        { id: `ev-d`, time: t, severity: 'info',     label: 'Correlation Created', method: '—',  path: chainId,   ip: '—',      detail: `${db.label} access correlated with ${ip.label}`,     delayMs: 5000 },
      ];
    },
    buildThreat(nodes, chainId) {
      return { badge: 'DATA EXFILTRATION', badgeColor: 'rose', title: 'Unauthorized Data Access', subtitle: nodes[3].label, confidence: 88, relatedEvents: 6, chain: chainId, firstSeen: 'Just now' };
    },
  },
  {
    name: 'Privilege Escalation',
    chainTypes: ['user', 'api', 'server', 'database'],
    buildEvents(nodes, chainId) {
      const user = nodes[0]; const api = nodes[1]; const srv = nodes[2];
      const t = now();
      return [
        { id: `ev-a`, time: t, severity: 'medium',   label: 'Suspicious Request',  method: 'POST', path: api.label, ip: '10.0.0.12', detail: `Elevated permission request from ${user.label}`, delayMs: 0    },
        { id: `ev-b`, time: t, severity: 'high',     label: 'Anomaly Detected',    method: 'POST', path: api.label, ip: '10.0.0.12', detail: `Role escalation to admin on ${srv.label}`,       delayMs: 1400 },
        { id: `ev-c`, time: t, severity: 'critical', label: 'Threat Identified',   method: 'POST', path: api.label, ip: '10.0.0.12', detail: 'Privilege escalation path confirmed',             delayMs: 2900 },
        { id: `ev-d`, time: t, severity: 'info',     label: 'Correlation Created', method: '—',   path: chainId,   ip: '—',         detail: `${user.label} escalation path fully mapped`,     delayMs: 4200 },
      ];
    },
    buildThreat(nodes, chainId) {
      return { badge: 'PRIVILEGE ESCALATION', badgeColor: 'violet', title: 'Unauthorized Role Escalation', subtitle: nodes[1].label, confidence: 85, relatedEvents: 5, chain: chainId, firstSeen: 'Just now' };
    },
  },
  {
    name: 'API Abuse',
    chainTypes: ['external_ip', 'api', 'server', 'database'],
    buildEvents(nodes, chainId) {
      const ip = nodes[0]; const api = nodes[1]; const srv = nodes[2];
      const t = now();
      return [
        { id: `ev-a`, time: t, severity: 'medium',   label: 'Suspicious Request',  method: 'GET', path: api.label, ip: ip.label, detail: 'Automated request fingerprint detected',             delayMs: 0    },
        { id: `ev-b`, time: t, severity: 'high',     label: 'Anomaly Detected',    method: 'GET', path: api.label, ip: ip.label, detail: `Rate limit bypassed on ${srv.label}`,                delayMs: 1300 },
        { id: `ev-c`, time: t, severity: 'critical', label: 'Threat Identified',   method: 'GET', path: api.label, ip: ip.label, detail: 'API enumeration/scraping in progress',               delayMs: 2700 },
        { id: `ev-d`, time: t, severity: 'info',     label: 'Correlation Created', method: '—',  path: chainId,   ip: '—',      detail: `${ip.label} exhaustive crawl of ${api.label}`,       delayMs: 4000 },
      ];
    },
    buildThreat(nodes, chainId) {
      return { badge: 'API ABUSE', badgeColor: 'indigo', title: 'Automated API Enumeration', subtitle: nodes[1].label, confidence: 83, relatedEvents: 9, chain: chainId, firstSeen: 'Just now' };
    },
  },
  {
    name: 'Credential Abuse',
    chainTypes: ['external_ip', 'user', 'api', 'server'],
    buildEvents(nodes, chainId) {
      const ip = nodes[0]; const user = nodes[1]; const api = nodes[2];
      const t = now();
      return [
        { id: `ev-a`, time: t, severity: 'medium',   label: 'Suspicious Request',  method: 'POST', path: api.label, ip: ip.label, detail: `Valid credentials from unknown geo: ${ip.label}`, delayMs: 0    },
        { id: `ev-b`, time: t, severity: 'high',     label: 'Anomaly Detected',    method: 'GET',  path: api.label, ip: ip.label, detail: `${user.label} signed in from new location`,       delayMs: 1600 },
        { id: `ev-c`, time: t, severity: 'critical', label: 'Threat Identified',   method: 'GET',  path: api.label, ip: ip.label, detail: `Account takeover attempt: ${user.label}`,         delayMs: 3100 },
        { id: `ev-d`, time: t, severity: 'info',     label: 'Correlation Created', method: '—',   path: chainId,   ip: '—',      detail: `${user.label} session linked to ${ip.label}`,     delayMs: 4600 },
      ];
    },
    buildThreat(nodes, chainId) {
      return { badge: 'CREDENTIAL ABUSE', badgeColor: 'amber', title: 'Account Takeover Attempt', subtitle: nodes[1].label, confidence: 79, relatedEvents: 7, chain: chainId, firstSeen: 'Just now' };
    },
  },
];

// ── Main Export ──────────────────────────────────────────────────────────────

export function generateAttack(): GeneratedAttack {
  const scenario = pick(SCENARIOS);
  const chainId  = `AC-${String(++chainSeq).padStart(3, '0')}`;

  // Pick nodes based on chain type sequence
  const chainNodes = scenario.chainTypes.map(type => {
    const pool = type === 'external_ip' ? IP_POOL
               : type === 'api'         ? API_POOL
               : type === 'user'        ? USER_POOL
               : type === 'server'      ? SERVER_POOL
               :                         DB_POOL;
    return pick(pool);
  });

  const chainEdges: GraphEdgeDef[] = chainNodes.slice(0, -1).map((node, i) => ({
    from: node.id,
    to: chainNodes[i + 1].id,
  }));

  const events  = scenario.buildEvents(chainNodes, chainId).map(e => ({
    ...e,
    id: `${e.id}-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  }));

  const threat = scenario.buildThreat(chainNodes, chainId);

  return { scenarioName: scenario.name, chainNodes, chainEdges, events, threat, chainId };
}
