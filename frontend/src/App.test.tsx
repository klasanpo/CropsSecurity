import { render, screen } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { App } from './App'

test('renders the Sprint 1 dashboard', () => {
  vi.stubGlobal('fetch', vi.fn(() => new Promise(() => undefined)))
  render(<App />)
  expect(screen.getByRole('heading', { name: 'CropsSecurity' })).toBeInTheDocument()
  expect(screen.getByText('0')).toBeInTheDocument()
  expect(screen.getByText('scanners instalados')).toBeInTheDocument()
})
