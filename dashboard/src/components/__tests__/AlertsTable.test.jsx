import React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import AlertsTable from '../AlertsTable'
import { DashboardProvider } from '../../contexts/DashboardContext'

import { MemoryRouter } from 'react-router-dom'

const renderWithProvider = (ui) => render(
  <DashboardProvider>
    <MemoryRouter>
      {ui}
    </MemoryRouter>
  </DashboardProvider>
)

vi.mock('../../services/api', () => ({
  getMetrics: vi.fn(),
  getAlerts: vi.fn(),
  getLiveTraffic: vi.fn(),
  getHealth: vi.fn(),
  getIncidents: vi.fn(),
}))

vi.mock('../../utils/auth', () => ({
  isAuthenticated: vi.fn(() => true),
  getToken: vi.fn(() => 'mock-token'),
  setToken: vi.fn(),
  clearAuth: vi.fn(),
}))

vi.mock('../../services/ws', () => ({
  subscribe: vi.fn(() => () => {}),
}))

import { getAlerts, getMetrics, getLiveTraffic, getHealth, getIncidents } from '../../services/api'

const makeAlert = (overrides = {}) => ({
  id: '1',
  timestamp: new Date().toISOString(),
  src_ip: '192.168.1.10',
  dst_ip: '10.0.0.1',
  attack_type: 'DDoS',
  composite_score: 0.75,
  severity: 'high',
  ...overrides,
})

beforeEach(() => {
  vi.clearAllMocks()
  getMetrics.mockResolvedValue({})
  getAlerts.mockResolvedValue([])
  getLiveTraffic.mockResolvedValue([])
  getHealth.mockResolvedValue({ status: 'healthy', database: 'ok', ml_models: {}, ollama: 'ok', agents: {} })
  getIncidents.mockResolvedValue([])
})

describe('AlertsTable', () => {
  // Requirement 14.1 — rendering
  it('renders "No alerts found" when getAlerts returns empty array', async () => {
    getAlerts.mockResolvedValue([])
    renderWithProvider(<AlertsTable />)
    await waitFor(() => {
      expect(screen.getByText('No alerts found')).toBeInTheDocument()
    })
  })

  it('renders all required columns (timestamp, src_ip, dst_ip, attack_type, score, severity)', async () => {
    const alert = makeAlert({
      timestamp: '2024-01-15T14:30:00.000Z',
      src_ip: '192.168.1.10',
      dst_ip: '10.0.0.1',
      attack_type: 'DDoS',
      composite_score: 0.7512,
      severity: 'high',
    })
    getAlerts.mockResolvedValue([alert])
    renderWithProvider(<AlertsTable />)

    await waitFor(() => {
      expect(screen.getByText('192.168.1.10')).toBeInTheDocument()
      expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
      expect(screen.getByText('DDoS')).toBeInTheDocument()
      expect(screen.getByText('0.7512')).toBeInTheDocument()
      expect(screen.getByText('HIGH')).toBeInTheDocument()
    })
  })

  // Requirement 14.1 — sorting
  it('sorts alerts by timestamp descending', async () => {
    const older = makeAlert({ id: '1', timestamp: '2024-01-15T10:00:00.000Z', src_ip: '1.1.1.1' })
    const newer = makeAlert({ id: '2', timestamp: '2024-01-15T12:00:00.000Z', src_ip: '2.2.2.2' })
    getAlerts.mockResolvedValue([older, newer])
    renderWithProvider(<AlertsTable />)

    await waitFor(() => {
      const ips = screen.getAllByText(/\d+\.\d+\.\d+\.\d+/)
      // newer (2.2.2.2) should appear before older (1.1.1.1)
      const texts = ips.map((el) => el.textContent)
      expect(texts.indexOf('2.2.2.2')).toBeLessThan(texts.indexOf('1.1.1.1'))
    })
  })

  // Requirement 14.1 — limit to 50 most recent
  it('displays at most 50 alerts even when more are returned', async () => {
    const alerts = Array.from({ length: 60 }, (_, i) =>
      makeAlert({
        id: String(i),
        src_ip: `10.0.0.${i % 256}`,
        // Spread timestamps so sorting is deterministic
        timestamp: new Date(Date.now() - i * 1000).toISOString(),
      })
    )
    getAlerts.mockResolvedValue(alerts)
    renderWithProvider(<AlertsTable />)

    await waitFor(() => {
      // Each row has a src_ip cell; count rows by looking for table rows
      const rows = screen.getAllByRole('row')
      // rows includes the header row, so data rows = rows.length - 1
      expect(rows.length - 1).toBeLessThanOrEqual(50)
    })
  })

  // Requirement 14.8 — error handling
  it('shows error message when getAlerts throws', async () => {
    getAlerts.mockRejectedValue(new Error('Network error'))
    renderWithProvider(<AlertsTable />)
    await waitFor(() => {
      expect(screen.getByText('Network error')).toBeInTheDocument()
    })
  })

  // Requirement 14.1 — detail panel (Req 14.6 in requirements)
  it('shows detail panel when a row is clicked', async () => {
    const alert = makeAlert({ src_ip: '192.168.1.99', attack_type: 'PortScan' })
    getAlerts.mockResolvedValue([alert])
    renderWithProvider(<AlertsTable />)

    await waitFor(() => {
      expect(screen.getByText('192.168.1.99')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('192.168.1.99'))

    await waitFor(() => {
      expect(screen.getByText('Attack Event Detail')).toBeInTheDocument()
    })
  })

  it('renders severity badge for critical alerts', async () => {
    getAlerts.mockResolvedValue([makeAlert({ severity: 'critical', composite_score: 0.95 })])
    renderWithProvider(<AlertsTable />)
    await waitFor(() => {
      expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    })
  })

  it('renders severity badge for medium alerts', async () => {
    getAlerts.mockResolvedValue([makeAlert({ severity: 'medium', composite_score: 0.67 })])
    renderWithProvider(<AlertsTable />)
    await waitFor(() => {
      expect(screen.getByText('MEDIUM')).toBeInTheDocument()
    })
  })
})
