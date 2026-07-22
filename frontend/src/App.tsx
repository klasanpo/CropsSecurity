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
  batch_id: string | null
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

type Comparison = {
  summary: { new: number; resolved: number; persistent: number }
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

const optionHelp: Record<string, { title: string; description: string; example: string; impact: string }> = {
  'Máximo por alvo': {
    title: 'Limite de segurança por alvo',
    description: 'Quantidade máxima de URLs e recursos únicos que podem ser visitados dentro de cada alvo. A URL inicial também entra na contagem.',
    example: 'Exemplo: 20 alvos com limite 200 permitem até 4.000 recursos. O limite é reiniciado para cada alvo.',
    impact: 'Aumentar melhora a cobertura, mas amplia o tempo de execução, o tráfego e o armazenamento.',
  },
  'Profundidade de navegação': {
    title: 'Profundidade de navegação',
    description: 'Define quantas camadas de referências serão seguidas a partir da URL inicial.',
    example: 'Nível 0 analisa somente a URL informada; nível 1 inclui referências diretas; nível 2 também percorre as referências encontradas nelas.',
    impact: 'A profundidade nunca ultrapassa o limite de recursos por alvo.',
  },
  'Tempo limite por recurso': {
    title: 'Tempo limite por recurso',
    description: 'Tempo máximo de espera para cada requisição HTTP individual.',
    example: 'Com 10 segundos, um recurso lento é interrompido após esse período e a análise continua nos demais.',
    impact: 'Valores altos ajudam em aplicações lentas, mas podem prolongar bastante o processamento.',
  },
  'Tamanho máximo por recurso': {
    title: 'Tamanho máximo por recurso',
    description: 'Quantidade máxima de conteúdo lida de cada HTML, JavaScript, JSON, log ou outro recurso textual.',
    example: 'Com 2 MB, um arquivo de 8 MB terá apenas os primeiros 2 MB analisados.',
    impact: 'Aumentar reduz o risco de perder dados no final de arquivos grandes, com maior consumo de memória.',
  },
  'Contexto da evidência': {
    title: 'Contexto antes e depois',
    description: 'Quantidade de caracteres preservada em cada lado do indicador encontrado.',
    example: 'O valor 1.500 salva até 1.500 caracteres anteriores e 1.500 posteriores, totalizando cerca de 3.000.',
    impact: 'Não altera a detecção; apenas aumenta o trecho disponível para análise e o espaço usado no banco.',
  },
  'Validar certificados TLS': {
    title: 'Validação de certificados TLS',
    description: 'Confirma se o certificado HTTPS é confiável, válido e corresponde ao servidor acessado.',
    example: 'Mantenha ativado para alvos públicos. Desative somente quando o escopo autorizado utilizar certificado interno ou autoassinado.',
    impact: 'Desativar aceita conexões cuja identidade não pôde ser confirmada.',
  },
  'Incluir referências externas': {
    title: 'Referências externas',
    description: 'Permite seguir recursos apontados para outros domínios além do alvo informado.',
    example: 'Uma página pode carregar JavaScript de um CDN ou chamar outro domínio. Desativado, esses endereços são ignorados.',
    impact: 'Ative somente quando os domínios externos também estiverem autorizados no escopo.',
  },
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
      api<Health>('/api/v1/health'), api<Module[]>('/api/v1/modules'), api<Scan[]>('/api/v1/scans?limit=100'),
    ])
    if (healthResult.status === 'fulfilled') setHealth(healthResult.value)
    if (modulesResult.status === 'fulfilled') setModules(modulesResult.value)
    if (scansResult.status === 'fulfilled') {
      setScans(scansResult.value)
      setSelectedScan((current) => current ? scansResult.value.find((scan) => scan.id === current.id) || null : current)
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

  const deleteExecution = async (scan: Scan) => {
    await api<{ status: string }>(`/api/v1/scans/${scan.id}`, { method: 'DELETE' })
    if (selectedScan?.id === scan.id) {
      setSelectedScan(null)
      setFindings([])
    }
    setNotice('Execução e resultados relacionados foram excluídos.')
    await refresh()
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
        {view === 'runs' && <Runs scans={scans} selected={selectedScan} findings={findings} onSelect={openScan} onDelete={deleteExecution} onCancel={async (scan) => { await api(`/api/v1/scans/${scan.id}/cancel`, { method: 'POST' }); setNotice('Cancelamento solicitado ao worker.'); await refresh() }} />}
      </main>

      {showLauncher && <ScanLauncher module={modules[0]} onClose={() => setShowLauncher(false)} onCreated={async (createdScans) => { setShowLauncher(false); setNotice(createdScans.length > 1 ? `Escopo com ${createdScans.length} alvos enviado para a fila.` : 'Análise enviada para a fila com sucesso.'); await refresh(); await openScan(createdScans[0]) }} />}
    </div>
  )
}

function NavButton({ active, icon, label, badge, onClick }: { active: boolean; icon: string; label: string; badge?: number; onClick: () => void }) {
  return <button className={active ? 'active' : ''} onClick={onClick}><span className="nav-icon">{icon}</span>{label}{badge !== undefined && <b>{badge}</b>}</button>
}

function Overview({ modules, scans, counts, health, onLaunch, onModules, onScan }: { modules: Module[]; scans: Scan[]; counts: { total: number; completed: number; findings: number; active: number }; health: Health; onLaunch: () => void; onModules: () => void; onScan: (scan: Scan) => void }) {
  return <div className="page-grid">
    <section className="hero-panel"><div className="hero-copy"><span className="release-tag">SPRINT 2 · PRIMEIRO MÓDULO</span><h2>Transforme superfície exposta em evidência acionável.</h2><p>Descubra segredos, dados pessoais e artefatos sensíveis em recursos web autorizados, com limites operacionais e evidências preservadas integralmente.</p><div className="hero-actions"><button className="primary-button large" onClick={onLaunch}>Iniciar análise</button><button className="secondary-button" onClick={onModules}>Conhecer ferramenta</button></div></div><div className="scanner-visual"><div className="radar-ring ring-1" /><div className="radar-ring ring-2" /><div className="radar-core">SD</div><span className="signal signal-a" /><span className="signal signal-b" /><span className="signal signal-c" /><div className="visual-label"><strong>{modules.length}</strong><span>módulo disponível</span></div></div></section>
    <section className="metric-grid"><Metric label="Execuções" value={counts.total} hint="histórico total" /><Metric label="Em andamento" value={counts.active} hint="fila e worker" accent /><Metric label="Concluídas" value={counts.completed} hint="processadas" /><Metric label="Achados" value={counts.findings} hint="todas as severidades" /></section>
    <section className="content-card recent"><div className="card-heading"><div><span className="section-kicker">ATIVIDADE</span><h3>Execuções recentes</h3></div><span className="muted">Últimas {Math.min(scans.length, 5)}</span></div>{scans.length ? <div className="run-list">{scans.slice(0, 5).map((scan) => <button key={scan.id} onClick={() => onScan(scan)}><StatusBadge status={scan.status} /><div className="run-main"><strong>{new URL(scan.target).hostname}</strong><span>{scan.phase}</span></div><div className="run-stat"><strong>{scan.findings_count}</strong><span>achados</span></div><time>{formatDate(scan.created_at)}</time><span className="arrow">→</span></button>)}</div> : <EmptyState title="Nenhuma análise executada" text="Inicie o primeiro assessment para construir seu histórico operacional." action="Executar agora" onAction={onLaunch} />}</section>
    <section className="content-card services"><div className="card-heading"><div><span className="section-kicker">INFRAESTRUTURA</span><h3>Saúde dos serviços</h3></div><span className="live-label"><i />Tempo real</span></div><div className="service-grid">{(Object.keys(serviceLabels) as Array<keyof Health>).map((key) => <div className="service" key={key}><span className={`service-icon ${health[key].status}`}>{serviceLabels[key].slice(0, 2).toUpperCase()}</span><div><strong>{serviceLabels[key]}</strong><span>{health[key].status === 'online' ? 'Operacional' : health[key].status === 'checking' ? 'Verificando' : 'Indisponível'}</span></div></div>)}</div></section>
  </div>
}

function Metric({ label, value, hint, accent }: { label: string; value: number; hint: string; accent?: boolean }) { return <article className={`metric-card ${accent ? 'accent' : ''}`}><span>{label}</span><strong>{String(value).padStart(2, '0')}</strong><small>{hint}</small></article> }

function Modules({ modules, onLaunch }: { modules: Module[]; onLaunch: () => void }) { return <div className="module-page"><div className="filter-bar"><span className="filter active">Todos <b>{modules.length}</b></span><span className="filter">Web <b>{modules.length}</b></span><span className="filter disabled">API <b>0</b></span><div className="search-box">⌕ <span>Buscar ferramentas</span></div></div>{modules.map((module) => <article className="module-card" key={module.id}><div className="module-accent"><span>SD</span><i>WEB</i></div><div className="module-body"><div className="module-title"><div><span className="available-dot">DISPONÍVEL</span><h2>{module.name}</h2><p>{module.short_name}</p></div><div className="impact-badge">Impacto {module.impact}</div></div><p className="module-description">{module.description}</p><div className="capabilities">{module.capabilities.map((item) => <span key={item}>{item}</span>)}</div><div className="module-meta"><span><small>Categoria</small>{module.category} / {module.subcategory}</span><span><small>Versão</small>{module.version}</span><span><small>Execução</small>Worker isolado</span></div><button className="primary-button" onClick={onLaunch}>Configurar análise →</button></div></article>)}</div> }

function Runs({ scans, selected, findings, onSelect, onDelete, onCancel }: { scans: Scan[]; selected: Scan | null; findings: Finding[]; onSelect: (scan: Scan) => void; onDelete: (scan: Scan) => Promise<void>; onCancel: (scan: Scan) => void }) {
  const [deleteCandidate, setDeleteCandidate] = useState<Scan | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const chooseScan = (scanId: string) => {
    const scan = scans.find((item) => item.id === scanId)
    if (scan) void onSelect(scan)
  }
  const confirmDelete = async () => {
    if (!deleteCandidate) return
    setDeleting(true); setDeleteError(null)
    try {
      await onDelete(deleteCandidate)
      setDeleteCandidate(null)
    } catch (reason) {
      setDeleteError(reason instanceof Error ? reason.message : 'Não foi possível excluir a execução.')
    } finally {
      setDeleting(false)
    }
  }
  return <div className="runs-layout"><section className="content-card run-selector-card"><div className="card-heading"><div><span className="section-kicker">RESULTADOS</span><h3>Selecione uma execução</h3></div><span className="muted">{scans.length} registros</span></div>{scans.length ? <><div className="run-selector-row"><label><span>Execução analisada</span><select aria-label="Selecionar execução" value={selected?.id || ''} onChange={(event) => chooseScan(event.target.value)}><option value="">Selecione um resultado</option>{scans.map((scan) => <option key={scan.id} value={scan.id}>{formatDate(scan.created_at)} · {new URL(scan.target).hostname} · {statusLabels[scan.status]} · {scan.findings_count} achados</option>)}</select></label>{selected && <button className="delete-button" disabled={['queued', 'running'].includes(selected.status)} onClick={() => { setDeleteError(null); setDeleteCandidate(selected) }}>Excluir execução</button>}</div>{selected && <div className="selected-run-summary"><StatusBadge status={selected.status} /><span><strong>{new URL(selected.target).hostname}</strong><small>{selected.phase}</small></span><span><strong>{selected.pages_scanned}</strong><small>recursos</small></span><span><strong>{selected.findings_count}</strong><small>achados</small></span><time>{formatDate(selected.created_at)}</time></div>}</> : <EmptyState title="Histórico vazio" text="As análises aparecerão aqui com progresso, resultados e trilha de execução." />}</section>{selected ? <ScanDetail key={selected.id} scan={selected} findings={findings} scans={scans} onSelect={onSelect} onCancel={() => onCancel(selected)} /> : scans.length > 0 && <section className="content-card result-placeholder"><EmptyState title="Escolha uma execução" text="Use o seletor acima para abrir os resultados em toda a largura da tela." /></section>}{deleteCandidate && <div className="modal-backdrop"><div className="delete-dialog" role="alertdialog" aria-modal="true" aria-labelledby="delete-dialog-title"><span className="delete-icon">×</span><span className="section-kicker">EXCLUSÃO PERMANENTE</span><h2 id="delete-dialog-title">Excluir esta execução?</h2><p>Serão removidos o histórico e os <strong>{deleteCandidate.findings_count} achados</strong> de <strong>{new URL(deleteCandidate.target).hostname}</strong>. Esta ação não pode ser desfeita.</p>{deleteError && <div className="form-error">{deleteError}</div>}<div><button className="secondary-button" disabled={deleting} onClick={() => setDeleteCandidate(null)}>Manter execução</button><button className="danger-button" disabled={deleting} onClick={() => void confirmDelete()}>{deleting ? 'Excluindo…' : 'Excluir definitivamente'}</button></div></div></div>}</div>
}

function ScanDetail({ scan, findings, scans, onSelect, onCancel }: { scan: Scan; findings: Finding[]; scans: Scan[]; onSelect: (scan: Scan) => void; onCancel: () => void }) {
  const [severityFilter, setSeverityFilter] = useState('')
  const [indicatorFilter, setIndicatorFilter] = useState('')
  const [search, setSearch] = useState('')
  const [baselineId, setBaselineId] = useState('')
  const [comparison, setComparison] = useState<Comparison | null>(null)
  const severityCounts = findings.reduce<Record<string, number>>((acc, finding) => ({ ...acc, [finding.severity]: (acc[finding.severity] || 0) + 1 }), {})
  const indicators = [...new Set(findings.map((finding) => finding.indicator))].sort()
  const visibleFindings = findings.filter((finding) => (!severityFilter || finding.severity === severityFilter) && (!indicatorFilter || finding.indicator === indicatorFilter) && (!search || `${finding.indicator} ${finding.category} ${finding.url}`.toLowerCase().includes(search.toLowerCase())))
  const batchMembers = scan.batch_id ? scans.filter((item) => item.batch_id === scan.batch_id) : []
  const baselines = scans.filter((item) => item.id !== scan.id && item.module_id === scan.module_id && item.target === scan.target && item.status === 'completed')
  const compare = async () => { if (baselineId) setComparison(await api<Comparison>(`/api/v1/scans/${scan.id}/comparison/${baselineId}`)) }
  return <section className="scan-detail"><div className="detail-head"><div><StatusBadge status={scan.status} /><h2>{new URL(scan.target).hostname}</h2><a href={scan.target} target="_blank" rel="noreferrer">{scan.target}</a></div>{['queued', 'running'].includes(scan.status) && <button className="danger-button" onClick={onCancel}>Cancelar</button>}</div>{batchMembers.length > 1 && <><div className="scope-panel"><div><span className="section-kicker">PAINEL DO ESCOPO</span><strong>{typeof scan.parameters.batch_label === 'string' ? scan.parameters.batch_label : `${batchMembers.length} alvos`}</strong></div><div className="scope-metrics"><span><b>{batchMembers.filter((item) => item.status === 'completed').length}</b> concluídos</span><span><b>{batchMembers.filter((item) => ['queued', 'running'].includes(item.status)).length}</b> em andamento</span><span><b>{batchMembers.reduce((total, item) => total + item.findings_count, 0)}</b> achados</span></div></div><div className="scope-targets">{batchMembers.map((item) => <button key={item.id} className={item.id === scan.id ? 'active' : ''} onClick={() => onSelect(item)}><StatusBadge status={item.status} /><span>{new URL(item.target).hostname}</span><b>{item.findings_count}</b></button>)}</div></>}<div className="progress-panel"><div><span>{scan.phase}</span><strong>{scan.progress}%</strong></div><i><b style={{ width: `${scan.progress}%` }} /></i><small>{scan.pages_scanned} recursos analisados</small></div><div className="severity-strip">{(['critical', 'high', 'medium', 'low'] as const).map((severity) => <div key={severity} className={severity}><strong>{severityCounts[severity] || 0}</strong><span>{severity === 'critical' ? 'Críticos' : severity === 'high' ? 'Altos' : severity === 'medium' ? 'Médios' : 'Baixos'}</span></div>)}</div>{scan.status === 'completed' && <><div className="result-tools"><div className="export-actions"><a href={`/api/v1/scans/${scan.id}/export/html`} download>HTML</a><a href={`/api/v1/scans/${scan.id}/export/csv`} download>CSV</a><a href={`/api/v1/scans/${scan.id}/export/json`} download>JSON</a></div>{baselines.length > 0 && <div className="retest-tools"><select value={baselineId} onChange={(event) => { setBaselineId(event.target.value); setComparison(null) }}><option value="">Comparar com teste anterior</option>{baselines.map((item) => <option key={item.id} value={item.id}>{formatDate(item.created_at)} · {item.findings_count} achados</option>)}</select><button disabled={!baselineId} onClick={() => void compare()}>Comparar</button></div>}</div>{comparison && <div className="comparison-strip"><span><b>{comparison.summary.new}</b> novos</span><span><b>{comparison.summary.resolved}</b> resolvidos</span><span><b>{comparison.summary.persistent}</b> persistentes</span></div>}</>}<div className="findings-head"><h3>Evidências encontradas</h3><span>{visibleFindings.length} de {findings.length}</span></div>{findings.length > 0 && <div className="finding-filters"><select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="">Todas as severidades</option>{Object.entries(severityLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select><select value={indicatorFilter} onChange={(event) => setIndicatorFilter(event.target.value)}><option value="">Todos os indicadores</option>{indicators.map((indicator) => <option key={indicator}>{indicator}</option>)}</select><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Buscar achado ou URL" /></div>}<div className="finding-list">{visibleFindings.map((finding) => <FindingCard finding={finding} key={finding.id} />)}{scan.status === 'completed' && !visibleFindings.length && <EmptyState title={findings.length ? 'Nenhum resultado no filtro' : 'Nenhum achado'} text={findings.length ? 'Ajuste os filtros para visualizar outros resultados.' : 'Nenhum indicador relevante foi identificado dentro dos limites configurados.'} />}</div>{scan.error && <div className="scan-warning"><strong>Recursos indisponíveis ou ignorados</strong><p>{scan.error}</p></div>}</section>
}

function FindingCard({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false)
  const canExpand = finding.snippet.length > 700 || finding.snippet.includes('\n')
  const visibleSnippet = expanded ? finding.snippet : focusedSnippet(finding.snippet, finding.match_text)
  return <article className={expanded ? 'expanded' : ''}><div className="finding-top"><span className={`severity ${finding.severity}`}>{severityLabels[finding.severity]}</span><span className="confidence">Confiança {confidenceLabels[finding.confidence] || finding.confidence}</span></div><h4>{finding.indicator}</h4><p>{finding.category} · {finding.file_name}:{finding.line}</p><code className={`evidence-code ${expanded ? 'expanded' : 'collapsed'}`}><HighlightedSnippet snippet={visibleSnippet} matchText={finding.match_text} /></code><div className="finding-actions">{canExpand && <button onClick={() => setExpanded((value) => !value)}>{expanded ? 'Recolher contexto ↑' : `Ver todo o contexto salvo (${finding.snippet.length.toLocaleString('pt-BR')} caracteres) ↓`}</button>}<a href={finding.url} target="_blank" rel="noreferrer">Abrir recurso ↗</a></div></article>
}

function focusedSnippet(snippet: string, matchText: string) {
  if (snippet.length <= 700) return snippet
  const matchIndex = matchText ? snippet.toLocaleLowerCase().indexOf(matchText.toLocaleLowerCase()) : -1
  if (matchIndex < 0) return snippet.slice(0, 700)
  const start = Math.max(0, matchIndex - 350)
  const end = Math.min(snippet.length, matchIndex + matchText.length + 350)
  const prefix = start > 0 ? '⟦ contexto anterior disponível ao expandir ⟧\n' : ''
  const suffix = end < snippet.length ? '\n⟦ contexto posterior disponível ao expandir ⟧' : ''
  return `${prefix}${snippet.slice(start, end)}${suffix}`
}

function HighlightedSnippet({ snippet, matchText }: { snippet: string; matchText: string }) {
  const index = matchText ? snippet.toLocaleLowerCase().indexOf(matchText.toLocaleLowerCase()) : -1
  if (index < 0) return <>{snippet}</>
  return <>{snippet.slice(0, index)}<mark>{snippet.slice(index, index + matchText.length)}</mark>{snippet.slice(index + matchText.length)}</>
}

function ScanLauncher({ module, onClose, onCreated }: { module?: Module; onClose: () => void; onCreated: (scans: Scan[]) => void }) {
  const [targetText, setTargetText] = useState('')
  const [batchLabel, setBatchLabel] = useState('')
  const [maxUrls, setMaxUrls] = useState(200)
  const [depth, setDepth] = useState(2)
  const [timeout, setTimeoutValue] = useState(10)
  const [maxMb, setMaxMb] = useState(2)
  const [verifyTls, setVerifyTls] = useState(true)
  const [includeExternal, setIncludeExternal] = useState(false)
  const [customWords, setCustomWords] = useState('')
  const [contextChars, setContextChars] = useState(1500)
  const [authorized, setAuthorized] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (event: FormEvent) => {
    event.preventDefault(); setSubmitting(true); setError(null)
    try {
      const targets = targetText.split(/\r?\n/).map((target) => target.trim()).filter((target) => target && !target.startsWith('#'))
      const parameters = { max_urls: maxUrls, depth, timeout_seconds: timeout, max_resource_bytes: maxMb * 1_000_000, include_external: includeExternal, verify_tls: verifyTls, custom_words: customWords.split(',').map((word) => word.trim()).filter(Boolean), context_chars: contextChars }
      if (targets.length > 1) {
        const created = await api<Scan[]>('/api/v1/scan-batches', { method: 'POST', body: JSON.stringify({ module_id: module?.id, targets, label: batchLabel || undefined, authorized, parameters }) })
        onCreated(created)
      } else {
        const created = await api<Scan>('/api/v1/scans', { method: 'POST', body: JSON.stringify({ module_id: module?.id, target: targets[0], authorized, parameters }) })
        onCreated([created])
      }
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Não foi possível iniciar a análise.'); setSubmitting(false) }
  }

  const targetCount = targetText.split(/\r?\n/).map((target) => target.trim()).filter((target) => target && !target.startsWith('#')).length
  const loadFile = async (file?: File) => { if (file) setTargetText(await file.text()) }

  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><form className="launcher" role="dialog" aria-modal="true" aria-labelledby="scan-launcher-title" onSubmit={submit}><header><div className="launcher-icon">SD</div><div><span className="section-kicker">WEB / EXPOSIÇÃO DE INFORMAÇÕES</span><h2 id="scan-launcher-title">{module?.name || 'Detector de Dados Sensíveis'}</h2><p>Configure uma URL ou um escopo com vários alvos autorizados.</p></div><button type="button" className="close-button" aria-label="Fechar configuração" onClick={onClose}>×</button></header><div className="form-body"><label className="full-field"><span>Alvos autorizados <em>{targetCount || 0} informado(s)</em></span><textarea value={targetText} onChange={(event) => setTargetText(event.target.value)} placeholder={'https://aplicacao.exemplo.com\nhttps://api.exemplo.com'} autoFocus required /><small>Informe uma URL por linha ou carregue um TXT. Linhas iniciadas por # serão ignoradas.</small></label><div className="upload-row"><label className="file-button">Carregar arquivo TXT<input type="file" accept=".txt,text/plain" onChange={(event) => void loadFile(event.target.files?.[0])} /></label><span>O limite de URLs abaixo vale separadamente para cada alvo.</span></div>{targetCount > 1 && <label className="full-field"><span>Nome do escopo <em>opcional</em></span><input type="text" value={batchLabel} onChange={(event) => setBatchLabel(event.target.value)} placeholder="Pentest Web — Cliente / Julho" /></label>}<div className="field-grid"><NumberField label="Máximo por alvo" value={maxUrls} min={1} max={500} onChange={setMaxUrls} suffix="URLs" /><NumberField label="Profundidade de navegação" value={depth} min={0} max={5} onChange={setDepth} suffix="níveis" /><NumberField label="Tempo limite por recurso" value={timeout} min={2} max={60} onChange={setTimeoutValue} suffix="seg" /><NumberField label="Tamanho máximo por recurso" value={maxMb} min={1} max={10} onChange={setMaxMb} suffix="MB" /><NumberField label="Contexto da evidência" value={contextChars} min={80} max={1500} onChange={setContextChars} suffix="caracteres" /></div><label className="full-field"><span>Palavras personalizadas <em>opcional</em></span><input type="text" value={customWords} onChange={(event) => setCustomWords(event.target.value)} placeholder="homologação, endpoint-interno, nome-do-projeto" /><small>Separe indicadores adicionais por vírgula.</small></label><div className="switch-grid"><Switch label="Validar certificados TLS" description="Recomendado para preservar a segurança da conexão." checked={verifyTls} onChange={setVerifyTls} /><Switch label="Incluir referências externas" description="Pode ampliar consideravelmente o escopo da análise." checked={includeExternal} onChange={setIncludeExternal} /></div><label className="authorization"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} required /><span><strong>Confirmo que possuo autorização para analisar todos os alvos informados.</strong><small>A execução e as evidências completas serão armazenadas no SQLite e poderão ser exportadas.</small></span></label>{error && <div className="form-error">{error}</div>}</div><footer><div><span className="impact-badge">Baixo impacto</span><small>O conteúdo encontrado será preservado sem alterações.</small></div><div><button type="button" className="secondary-button" onClick={onClose}>Cancelar</button><button className="primary-button" disabled={!authorized || !targetCount || submitting}>{submitting ? 'Enviando…' : targetCount > 1 ? `Analisar ${targetCount} alvos →` : 'Iniciar análise →'}</button></div></footer></form></div>
}

function NumberField({ label, value, min, max, suffix, onChange }: { label: string; value: number; min: number; max: number; suffix: string; onChange: (value: number) => void }) { const isEvidenceContext = label === 'Contexto da evidência'; const displayLabel = label === 'Máximo por alvo' ? 'Limite de segurança por alvo' : isEvidenceContext ? 'Contexto antes e depois' : label; return <label><span className="field-label">{displayLabel}<OptionHelp option={label} /></span><div className="number-input"><input type="number" value={value} min={min} max={max} onChange={(event) => onChange(Number(event.target.value))} /><b>{isEvidenceContext ? 'carac./lado' : suffix}</b></div>{isEvidenceContext && <small>O valor é preservado em cada lado do achado; 1.500 gera até 3.000 caracteres de contexto.</small>}</label> }
function Switch({ label, description, checked, onChange }: { label: string; description: string; checked: boolean; onChange: (value: boolean) => void }) { return <div className="switch"><label className="switch-control"><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} /><i><b /></i><span><strong>{label}</strong><small>{description}</small></span></label><OptionHelp option={label} /></div> }
function OptionHelp({ option }: { option: string }) {
  const [open, setOpen] = useState(false)
  const help = optionHelp[option]
  if (!help) return null
  return <span className="option-help" onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)} onFocusCapture={() => setOpen(true)} onBlurCapture={(event) => { const next = event.relatedTarget as Node | null; if (!next || !event.currentTarget.contains(next)) setOpen(false) }}><button type="button" aria-label={`Ajuda: ${help.title}`} aria-expanded={open} onClick={(event) => { event.preventDefault(); event.stopPropagation(); setOpen((value) => !value) }}>?</button>{open && <span className="option-help-panel" role="note"><strong>{help.title}</strong><p>{help.description}</p><em>Exemplo</em><p>{help.example}</p><small>{help.impact}</small></span>}</span>
}
function StatusBadge({ status }: { status: Scan['status'] }) { return <span className={`status-badge ${status}`}><i />{statusLabels[status]}</span> }
function EmptyState({ title, text, action, onAction }: { title: string; text: string; action?: string; onAction?: () => void }) { return <div className="empty-state"><span>◎</span><strong>{title}</strong><p>{text}</p>{action && <button onClick={onAction}>{action} →</button>}</div> }
