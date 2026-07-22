import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react'

type ServiceStatus = 'online' | 'offline' | 'checking'
type Health = Record<'backend' | 'database' | 'redis' | 'worker', { status: ServiceStatus }>
type View = 'overview' | 'modules' | 'runs'

type Module = {
  id: string
  name: string
  short_name: string
  category: string
  subcategory: string
  description: string
  impact: string
  version: string
  status: string
  capabilities: string[]
}

type Scan = {
  id: string
  module_id: string
  target: string
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress: number
  phase: string
  parameters: Record<string, unknown>
  pages_scanned: number
  findings_count: number
  error: string | null
  created_at: string
  started_at: string | null
  finished_at: string | null
  cancel_requested: boolean
}

type Finding = {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informative'
  confidence: string
  category: string
  indicator: string
  url: string
  file_name: string
  line: number
  snippet: string
  match_text: string
}

const initialHealth: Health = {
  backend: { status: 'checking' },
  database: { status: 'checking' },
  redis: { status: 'checking' },
  worker: { status: 'checking' },
}

const serviceLabels: Record<keyof Health, string> = {
  backend: 'Backend', database: 'SQLite', redis: 'Redis', worker: 'Worker',
}

const statusLabels: Record<Scan['status'], string> = {
  queued: 'Na fila', running: 'Executando', completed: 'Concluído', failed: 'Falhou', cancelled: 'Cancelado',
}

const severityLabels: Record<Finding['severity'], string> = {
  critical: 'Crítico', high: 'Alto', medium: 'Médio', low: 'Baixo', informative: 'Informativo',
}

const confidenceLabels: Record<string, string> = {
  confirmed: 'Confirmada', high: 'Alta', medium: 'Média', low: 'Baixa',
}

function formatDate(value: string | null) {
  if (!value) return '—'
  return new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value))
}

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options?.headers || {}) },
  })
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ detail: 'Não foi possível concluir a operação.' }))
    throw new Error(payload.detail || 'Não foi possível concluir a operação.')
  }
  return response.json()
}

export function App() {
  const [view, setView] = useState<View>('overview')
  const [health, setHealth] = useState<Health>(initialHealth)
  const [modules, setModules] = useState<Module[]>([])
  const [scans, setScans] = useState<Scan[]>([])
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [showLauncher, setShowLauncher] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    const [healthResult, modulesResult, scansResult] = await Promise.allSettled([
      api<Health>('/api/v1/health'), api<Module[]>('/api/v1/modules'), api<Scan[]>('/api/v1/scans'),
    ])
    if (healthResult.status === 'fulfilled') setHealth(healthResult.value)
    if (modulesResult.status === 'fulfilled') setModules(modulesResult.value)
    if (scansResult.status === 'fulfilled') {
      setScans(scansResult.value)
      setSelectedScan((current) => current ? scansResult.value.find((scan) => scan.id === current.id) || current : current)
    }
  }, [])

  useEffect(() => {
    const timer = window.setTimeout(() => void refresh(), 0)
    return () => window.clearTimeout(timer)
  }, [refresh])
  useEffect(() => {
    if (!scans.some((scan) => scan.status === 'queued' || scan.status === 'running')) return
    const timer = window.setInterval(() => void refresh(), 1800)
    return () => window.clearInterval(timer)
  }, [scans, refresh])

  useEffect(() => {
    if (!selectedScan) return
    const timer = window.setTimeout(async () => {
      try {
        setFindings(await api<Finding[]>(`/api/v1/scans/${selectedScan.id}/findings`))
      } catch {
        setFindings([])
      }
    }, 0)
    return () => window.clearTimeout(timer)
  }, [selectedScan])

  const openScan = async (scan: Scan) => {
    setSelectedScan(scan)
    setView('runs')
    try { setFindings(await api<Finding[]>(`/api/v1/scans/${scan.id}/findings`)) } catch { setFindings([]) }
  }

  const counts = useMemo(() => ({
    total: scans.length,
    completed: scans.filter((scan) => scan.status === 'completed').length,
    findings: scans.reduce((total, scan) => total + scan.findings_count, 0),
    active: scans.filter((scan) => ['queued', 'running'].includes(scan.status)).length,
  }), [scans])

  const allHealthy = Object.values(health).every((service) => service.status === 'online')

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">CS</span><div><strong>CropsSecurity</strong><small>Security workspace</small></div></div>
        <nav aria-label="Navegação principal">
          <NavButton active={view === 'overview'} icon="01" label="Visão geral" onClick={() => setView('overview')} />
          <NavButton active={view === 'modules'} icon="02" label="Ferramentas" badge={modules.length} onClick={() => setView('modules')} />
          <NavButton active={view === 'runs'} icon="03" label="Execuções" badge={counts.active || undefined} onClick={() => setView('runs')} />
        </nav>
        <div className="sidebar-section"><span>Áreas</span><button><i className="area-dot web" />Web <b>{modules.length}</b></button><button disabled><i className="area-dot api" />API <b>0</b></button><button disabled><i className="area-dot cloud" />Cloud <b>0</b></button></div>
        <div className="sidebar-status"><span className={`status-orb ${allHealthy ? 'online' : 'warning'}`} /><div><strong>{allHealthy ? 'Sistema operacional' : 'Verificando serviços'}</strong><small>Ambiente local · :1984</small></div></div>
      </aside>

      <main className="workspace">
        <header className="topbar"><div><span className="breadcrumb">CROPS / {view === 'overview' ? 'VISÃO GERAL' : view === 'modules' ? 'FERRAMENTAS' : 'EXECUÇÕES'}</span><h1>{view === 'overview' ? 'Central de operações' : view === 'modules' ? 'Catálogo de ferramentas' : 'Histórico de execuções'}</h1></div><button className="primary-button" disabled={!modules.length} onClick={() => setShowLauncher(true)}><span>＋</span> Nova análise</button></header>

        {notice && <div className="notice" role="status"><span>✓</span>{notice}<button onClick={() => setNotice(null)}>×</button></div>}
        {view === 'overview' && <Overview modules={modules} scans={scans} counts={counts} health={health} onLaunch={() => setShowLauncher(true)} onModules={() => setView('modules')} onScan={openScan} />}
        {view === 'modules' && <Modules modules={modules} onLaunch={() => setShowLauncher(true)} />}
        {view === 'runs' && <Runs scans={scans} selected={selectedScan} findings={findings} onSelect={openScan} onCancel={async (scan) => { await api(`/api/v1/scans/${scan.id}/cancel`, { method: 'POST' }); setNotice('Cancelamento solicitado ao worker.'); await refresh() }} />}
      </main>

      {showLauncher && <ScanLauncher module={modules[0]} onClose={() => setShowLauncher(false)} onCreated={async (scan) => { setShowLauncher(false); setNotice('Análise enviada para a fila com sucesso.'); await refresh(); await openScan(scan) }} />}
    </div>
  )
}

function NavButton({ active, icon, label, badge, onClick }: { active: boolean; icon: string; label: string; badge?: number; onClick: () => void }) {
  return <button className={active ? 'active' : ''} onClick={onClick}><span className="nav-icon">{icon}</span>{label}{badge !== undefined && <b>{badge}</b>}</button>
}

function Overview({ modules, scans, counts, health, onLaunch, onModules, onScan }: { modules: Module[]; scans: Scan[]; counts: { total: number; completed: number; findings: number; active: number }; health: Health; onLaunch: () => void; onModules: () => void; onScan: (scan: Scan) => void }) {
  return <div className="page-grid">
    <section className="hero-panel"><div className="hero-copy"><span className="release-tag">SPRINT 2 · PRIMEIRO MÓDULO</span><h2>Transforme superfície exposta em evidência acionável.</h2><p>Descubra segredos, dados pessoais e artefatos sensíveis em recursos web autorizados, com limites operacionais e valores mascarados por padrão.</p><div className="hero-actions"><button className="primary-button large" onClick={onLaunch}>Iniciar análise</button><button className="secondary-button" onClick={onModules}>Conhecer ferramenta</button></div></div><div className="scanner-visual"><div className="radar-ring ring-1" /><div className="radar-ring ring-2" /><div className="radar-core">SD</div><span className="signal signal-a" /><span className="signal signal-b" /><span className="signal signal-c" /><div className="visual-label"><strong>{modules.length}</strong><span>módulo disponível</span></div></div></section>
    <section className="metric-grid"><Metric label="Execuções" value={counts.total} hint="histórico total" /><Metric label="Em andamento" value={counts.active} hint="fila e worker" accent /><Metric label="Concluídas" value={counts.completed} hint="processadas" /><Metric label="Achados" value={counts.findings} hint="todas as severidades" /></section>
    <section className="content-card recent"><div className="card-heading"><div><span className="section-kicker">ATIVIDADE</span><h3>Execuções recentes</h3></div><span className="muted">Últimas {Math.min(scans.length, 5)}</span></div>{scans.length ? <div className="run-list">{scans.slice(0, 5).map((scan) => <button key={scan.id} onClick={() => onScan(scan)}><StatusBadge status={scan.status} /><div className="run-main"><strong>{new URL(scan.target).hostname}</strong><span>{scan.phase}</span></div><div className="run-stat"><strong>{scan.findings_count}</strong><span>achados</span></div><time>{formatDate(scan.created_at)}</time><span className="arrow">→</span></button>)}</div> : <EmptyState title="Nenhuma análise executada" text="Inicie o primeiro assessment para construir seu histórico operacional." action="Executar agora" onAction={onLaunch} />}</section>
    <section className="content-card services"><div className="card-heading"><div><span className="section-kicker">INFRAESTRUTURA</span><h3>Saúde dos serviços</h3></div><span className="live-label"><i />Tempo real</span></div><div className="service-grid">{(Object.keys(serviceLabels) as Array<keyof Health>).map((key) => <div className="service" key={key}><span className={`service-icon ${health[key].status}`}>{serviceLabels[key].slice(0, 2).toUpperCase()}</span><div><strong>{serviceLabels[key]}</strong><span>{health[key].status === 'online' ? 'Operacional' : health[key].status === 'checking' ? 'Verificando' : 'Indisponível'}</span></div></div>)}</div></section>
  </div>
}

function Metric({ label, value, hint, accent }: { label: string; value: number; hint: string; accent?: boolean }) { return <article className={`metric-card ${accent ? 'accent' : ''}`}><span>{label}</span><strong>{String(value).padStart(2, '0')}</strong><small>{hint}</small></article> }

function Modules({ modules, onLaunch }: { modules: Module[]; onLaunch: () => void }) { return <div className="module-page"><div className="filter-bar"><span className="filter active">Todos <b>{modules.length}</b></span><span className="filter">Web <b>{modules.length}</b></span><span className="filter disabled">API <b>0</b></span><div className="search-box">⌕ <span>Buscar ferramentas</span></div></div>{modules.map((module) => <article className="module-card" key={module.id}><div className="module-accent"><span>SD</span><i>WEB</i></div><div className="module-body"><div className="module-title"><div><span className="available-dot">DISPONÍVEL</span><h2>{module.name}</h2><p>{module.short_name}</p></div><div className="impact-badge">Impacto {module.impact}</div></div><p className="module-description">{module.description}</p><div className="capabilities">{module.capabilities.map((item) => <span key={item}>{item}</span>)}</div><div className="module-meta"><span><small>Categoria</small>{module.category} / {module.subcategory}</span><span><small>Versão</small>{module.version}</span><span><small>Execução</small>Worker isolado</span></div><button className="primary-button" onClick={onLaunch}>Configurar análise →</button></div></article>)}</div> }

function Runs({ scans, selected, findings, onSelect, onCancel }: { scans: Scan[]; selected: Scan | null; findings: Finding[]; onSelect: (scan: Scan) => void; onCancel: (scan: Scan) => void }) {
  return <div className={`runs-layout ${selected ? 'with-detail' : ''}`}><section className="content-card runs-card"><div className="card-heading"><div><span className="section-kicker">HISTÓRICO</span><h3>Todas as execuções</h3></div><span className="muted">{scans.length} registros</span></div>{scans.length ? <div className="runs-table"><div className="table-head"><span>Status</span><span>Alvo</span><span>Progresso</span><span>Achados</span><span>Início</span></div>{scans.map((scan) => <button className={selected?.id === scan.id ? 'selected' : ''} key={scan.id} onClick={() => onSelect(scan)}><StatusBadge status={scan.status} /><span className="target-cell"><strong>{new URL(scan.target).hostname}</strong><small>{scan.phase}</small></span><span className="progress-cell"><i><b style={{ width: `${scan.progress}%` }} /></i><small>{scan.progress}%</small></span><strong>{scan.findings_count}</strong><time>{formatDate(scan.created_at)}</time></button>)}</div> : <EmptyState title="Histórico vazio" text="As análises aparecerão aqui com progresso, resultados e trilha de execução." />}</section>{selected && <ScanDetail scan={selected} findings={findings} onCancel={() => onCancel(selected)} />}</div>
}

function ScanDetail({ scan, findings, onCancel }: { scan: Scan; findings: Finding[]; onCancel: () => void }) {
  const severityCounts = findings.reduce<Record<string, number>>((acc, finding) => ({ ...acc, [finding.severity]: (acc[finding.severity] || 0) + 1 }), {})
  return <aside className="scan-detail"><div className="detail-head"><div><StatusBadge status={scan.status} /><h2>{new URL(scan.target).hostname}</h2><a href={scan.target} target="_blank" rel="noreferrer">{scan.target}</a></div>{['queued', 'running'].includes(scan.status) && <button className="danger-button" onClick={onCancel}>Cancelar</button>}</div><div className="progress-panel"><div><span>{scan.phase}</span><strong>{scan.progress}%</strong></div><i><b style={{ width: `${scan.progress}%` }} /></i><small>{scan.pages_scanned} recursos analisados</small></div><div className="severity-strip">{(['critical', 'high', 'medium', 'low'] as const).map((severity) => <div key={severity} className={severity}><strong>{severityCounts[severity] || 0}</strong><span>{severity === 'critical' ? 'Críticos' : severity === 'high' ? 'Altos' : severity === 'medium' ? 'Médios' : 'Baixos'}</span></div>)}</div><div className="findings-head"><h3>Achados</h3><span>{findings.length} resultados</span></div><div className="finding-list">{findings.map((finding) => <article key={finding.id}><div className="finding-top"><span className={`severity ${finding.severity}`}>{severityLabels[finding.severity]}</span><span className="confidence">Confiança {confidenceLabels[finding.confidence] || finding.confidence}</span></div><h4>{finding.indicator}</h4><p>{finding.category} · {finding.file_name}:{finding.line}</p><code>{finding.snippet}</code><a href={finding.url} target="_blank" rel="noreferrer">Abrir recurso ↗</a></article>)}{scan.status === 'completed' && !findings.length && <EmptyState title="Nenhum achado" text="Nenhum indicador relevante foi identificado dentro dos limites configurados." />}</div>{scan.error && <div className="scan-warning"><strong>Observações da execução</strong><p>{scan.error}</p></div>}</aside>
}

function ScanLauncher({ module, onClose, onCreated }: { module?: Module; onClose: () => void; onCreated: (scan: Scan) => void }) {
  const [target, setTarget] = useState('')
  const [maxUrls, setMaxUrls] = useState(80)
  const [depth, setDepth] = useState(2)
  const [timeout, setTimeoutValue] = useState(10)
  const [maxMb, setMaxMb] = useState(2)
  const [verifyTls, setVerifyTls] = useState(true)
  const [includeExternal, setIncludeExternal] = useState(false)
  const [customWords, setCustomWords] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (event: FormEvent) => {
    event.preventDefault(); setSubmitting(true); setError(null)
    try {
      const scan = await api<Scan>('/api/v1/scans', { method: 'POST', body: JSON.stringify({ module_id: module?.id, target, authorized, parameters: { max_urls: maxUrls, depth, timeout_seconds: timeout, max_resource_bytes: maxMb * 1_000_000, include_external: includeExternal, verify_tls: verifyTls, custom_words: customWords.split(',').map((word) => word.trim()).filter(Boolean) } }) })
      onCreated(scan)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Não foi possível iniciar a análise.'); setSubmitting(false) }
  }

  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><form className="launcher" role="dialog" aria-modal="true" aria-labelledby="scan-launcher-title" onSubmit={submit}><header><div className="launcher-icon">SD</div><div><span className="section-kicker">WEB / EXPOSIÇÃO DE INFORMAÇÕES</span><h2 id="scan-launcher-title">{module?.name || 'Detector de Dados Sensíveis'}</h2><p>Configure limites operacionais para uma análise controlada.</p></div><button type="button" className="close-button" aria-label="Fechar configuração" onClick={onClose}>×</button></header><div className="form-body"><label className="full-field"><span>URL autorizada</span><input type="text" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://aplicacao.exemplo.com" autoFocus required /><small>O scanner permanecerá no mesmo domínio, salvo autorização explícita abaixo.</small></label><div className="field-grid"><NumberField label="Limite de páginas e recursos" value={maxUrls} min={1} max={500} onChange={setMaxUrls} suffix="URLs" /><NumberField label="Profundidade de navegação" value={depth} min={0} max={5} onChange={setDepth} suffix="níveis" /><NumberField label="Tempo limite por recurso" value={timeout} min={2} max={60} onChange={setTimeoutValue} suffix="seg" /><NumberField label="Tamanho máximo por recurso" value={maxMb} min={1} max={10} onChange={setMaxMb} suffix="MB" /></div><label className="full-field"><span>Palavras personalizadas <em>opcional</em></span><input type="text" value={customWords} onChange={(event) => setCustomWords(event.target.value)} placeholder="homologação, endpoint-interno, nome-do-projeto" /><small>Separe indicadores adicionais por vírgula.</small></label><div className="switch-grid"><Switch label="Validar certificados TLS" description="Recomendado para preservar a segurança da conexão." checked={verifyTls} onChange={setVerifyTls} /><Switch label="Incluir referências externas" description="Pode ampliar consideravelmente o escopo da análise." checked={includeExternal} onChange={setIncludeExternal} /></div><label className="authorization"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} required /><span><strong>Confirmo que possuo autorização para analisar este alvo.</strong><small>A execução será registrada com os parâmetros e horário informados.</small></span></label>{error && <div className="form-error">{error}</div>}</div><footer><div><span className="impact-badge">Baixo impacto</span><small>Valores sensíveis serão mascarados.</small></div><div><button type="button" className="secondary-button" onClick={onClose}>Cancelar</button><button className="primary-button" disabled={!authorized || submitting}>{submitting ? 'Enviando…' : 'Iniciar análise →'}</button></div></footer></form></div>
}

function NumberField({ label, value, min, max, suffix, onChange }: { label: string; value: number; min: number; max: number; suffix: string; onChange: (value: number) => void }) { return <label><span>{label}</span><div className="number-input"><input type="number" value={value} min={min} max={max} onChange={(event) => onChange(Number(event.target.value))} /><b>{suffix}</b></div></label> }
function Switch({ label, description, checked, onChange }: { label: string; description: string; checked: boolean; onChange: (value: boolean) => void }) { return <label className="switch"><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} /><i><b /></i><span><strong>{label}</strong><small>{description}</small></span></label> }
function StatusBadge({ status }: { status: Scan['status'] }) { return <span className={`status-badge ${status}`}><i />{statusLabels[status]}</span> }
function EmptyState({ title, text, action, onAction }: { title: string; text: string; action?: string; onAction?: () => void }) { return <div className="empty-state"><span>◎</span><strong>{title}</strong><p>{text}</p>{action && <button onClick={onAction}>{action} →</button>}</div> }
