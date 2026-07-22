import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'

import { App } from './App'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

test('renders the professional operations workspace', async () => {
  const module = {
    id: 'web.sensitive-data-finder', name: 'Detector de Dados Sensíveis', short_name: 'Sensitive Data Finder',
    category: 'Web', subcategory: 'Exposição de Informações', description: 'Localiza dados sensíveis.',
    impact: 'Baixo', version: '1.1.0', status: 'available', capabilities: ['Segredos'],
  }
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    const payload = url.includes('/health')
      ? { backend: { status: 'online' }, database: { status: 'online' }, redis: { status: 'online' }, worker: { status: 'online' } }
      : url.includes('/modules') ? [module] : []
    return { ok: true, json: async () => payload } as Response
  }))
  render(<App />)
  expect(screen.getByRole('heading', { name: 'Central de operações' })).toBeInTheDocument()
  const launchButton = screen.getByRole('button', { name: /Nova análise/i })
  await waitFor(() => expect(launchButton).toBeEnabled())
  expect(await screen.findByText('Sistema operacional')).toBeInTheDocument()

  fireEvent.click(launchButton)
  expect(screen.getByDisplayValue('200')).toBeInTheDocument()
  const helpButton = screen.getByRole('button', { name: 'Ajuda: Limite de segurança por alvo' })
  const helpContainer = helpButton.closest('.option-help')
  expect(helpContainer).not.toBeNull()
  fireEvent.mouseEnter(helpContainer!)
  expect(screen.getByText(/20 alvos com limite 200 permitem até 4.000 recursos/)).toBeInTheDocument()
  fireEvent.mouseLeave(helpContainer!)
  expect(screen.queryByText(/20 alvos com limite 200 permitem até 4.000 recursos/)).not.toBeInTheDocument()
})

test('selects, expands, highlights and deletes a finished execution', async () => {
  const scan = {
    id: 'scan-001', module_id: 'web.sensitive-data-finder', target: 'https://app.example.test/',
    status: 'completed', progress: 100, phase: 'Concluído', parameters: { context_chars: 1500 }, pages_scanned: 4,
    findings_count: 1, error: null, created_at: '2026-07-22T12:00:00Z', started_at: null,
    finished_at: '2026-07-22T12:01:00Z', cancel_requested: false, batch_id: null,
  }
  const exactMatch = 'password = ProductionSecret17'
  const finding = {
    id: 'finding-001', severity: 'high', confidence: 'high', category: 'Credencial',
    indicator: 'Assignment: password', url: 'https://app.example.test/app.js', file_name: 'app.js',
    line: 14, snippet: `${'contexto '.repeat(170)}${exactMatch}${' posterior'.repeat(150)}`,
    match_text: exactMatch,
  }
  const fetchMock = vi.fn(async (input: RequestInfo | URL, options?: RequestInit) => {
    const url = String(input)
    if (options?.method === 'DELETE') return { ok: true, json: async () => ({ status: 'deleted' }) } as Response
    if (url.includes('/health')) return { ok: true, json: async () => ({ backend: { status: 'online' }, database: { status: 'online' }, redis: { status: 'online' }, worker: { status: 'online' } }) } as Response
    if (url.includes('/modules')) return { ok: true, json: async () => [] } as Response
    if (url.includes('/findings')) return { ok: true, json: async () => [finding] } as Response
    if (url.includes('/scans')) return { ok: true, json: async () => [scan] } as Response
    return { ok: true, json: async () => ({}) } as Response
  })
  vi.stubGlobal('fetch', fetchMock)
  const { container } = render(<App />)

  fireEvent.click(await screen.findByRole('button', { name: /Execuções/ }))
  fireEvent.change(await screen.findByLabelText('Selecionar execução'), { target: { value: 'scan-001' } })
  expect(await screen.findByRole('heading', { name: 'app.example.test' })).toBeInTheDocument()
  expect(await screen.findByText(exactMatch)).toBeInTheDocument()
  expect(container.querySelector('mark')?.textContent).toBe(exactMatch)

  fireEvent.click(screen.getByRole('button', { name: /Ver todo o contexto salvo/ }))
  expect(container.querySelector('.evidence-code.expanded')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Excluir execução' }))
  fireEvent.click(screen.getByRole('button', { name: 'Excluir definitivamente' }))
  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/v1/scans/scan-001', expect.objectContaining({ method: 'DELETE' })))
})
