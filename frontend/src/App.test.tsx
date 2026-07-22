import { render, screen } from '@testing-library/react'
import { expect, test, vi } from 'vitest'

import { App } from './App'

test('renders the professional operations workspace', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    const payload = url.includes('/health')
      ? { backend: { status: 'online' }, database: { status: 'online' }, redis: { status: 'online' }, worker: { status: 'online' } }
      : []
    return { ok: true, json: async () => payload } as Response
  }))
  render(<App />)
  expect(screen.getByRole('heading', { name: 'Central de operações' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: /Nova análise/i })).toBeInTheDocument()
  expect(await screen.findByText('Sistema operacional')).toBeInTheDocument()
})
