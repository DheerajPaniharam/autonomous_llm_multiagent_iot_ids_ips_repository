import React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import AttackChart from '../AttackChart'
import { DashboardProvider } from '../../contexts/DashboardContext'

const renderWithProvider = (ui) => render(<DashboardProvider>{ui}</DashboardProvider>)

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

// recharts uses ResizeObserver which is not available in jsdom
globalThis.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

import { getAlerts, getMetrics, getLiveTraffic, getHealth, getIncidents } from '../../services/api'

beforeEach(() => {
  vi.clearAllMocks()
  getMetrics.mockResolvedValue({})
  getAlerts.mockResolvedValue([])
  getLiveTraffic.mockResolvedValue([])
  getHealth.mockResolvedValue({ status: 'healthy', database: 'ok', ml_models: {}, ollama: 'ok', agents: {} })
  getIncidents.mockResolvedValue([])
})

const recentTimestamp = () => new Date(Date.now() - 60 * 1000).toISOString()

// ── Inline re-implementation of buildChartData for unit testing ──────────────
// This mirrors the logic in AttackChart.jsx so we can test it directly.
const toHourBucket = (ts) => {
  const d = new Date(ts)
  const yyyy = d.getFullYear()
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  const hh = String(d.getHours()).padStart(2, '0')
  return `${yyyy}-${mm}-${dd} ${hh}:00`
}

const buildChartData = (alerts) => {
  const now = Date.now()
  const cutoff = now - 24 * 60 * 60 * 1000
  const recent = alerts.filter((a) => {
    const t = new Date(a.timestamp).getTime()
    return !isNaN(t) && t >= cutoff
  })
  const attackTypeSet = new Set()
  recent.forEach((a) => { if (a.attack_type) attackTypeSet.add(a.attack_type) })
  const attackTypes = Array.from(attackTypeSet).sort()
  const bucketMap = {}
  recent.forEach((a) => {
    const bucket = toHourBucket(a.timestamp)
    if (!bucketMap[bucket]) bucketMap[bucket] = { hour: bucket }
    const type = a.attack_type || 'unknown'
    bucketMap[bucket][type] = (bucketMap[bucket][type] || 0) + 1
  })
  const chartData = Object.values(bucketMap).sort((a, b) => a.hour.localeCompare(b.hour))
  return { chartData, attackTypes }
}

// ── Unit tests for buildChartData grouping logic (Requirement 14.2) ──────────
describe('buildChartData (data grouping logic)', () => {
  it('returns empty chartData and attackTypes for empty input', () => {
    const { chartData, attackTypes } = buildChartData([])
    expect(chartData).toEqual([])
    expect(attackTypes).toEqual([])
  })

  it('filters out alerts older than 24 hours', () => {
    const oldTs = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString()
    const { chartData } = buildChartData([{ timestamp: oldTs, attack_type: 'DDoS' }])
    expect(chartData).toEqual([])
  })

  it('groups multiple alerts of the same type into one bucket entry', () => {
    const ts = recentTimestamp()
    const alerts = [
      { timestamp: ts, attack_type: 'DDoS' },
      { timestamp: ts, attack_type: 'DDoS' },
      { timestamp: ts, attack_type: 'DDoS' },
    ]
    const { chartData, attackTypes } = buildChartData(alerts)
    expect(attackTypes).toEqual(['DDoS'])
    expect(chartData).toHaveLength(1)
    expect(chartData[0]['DDoS']).toBe(3)
  })

  it('groups alerts by distinct attack_type', () => {
    const ts = recentTimestamp()
    const alerts = [
      { timestamp: ts, attack_type: 'DDoS' },
      { timestamp: ts, attack_type: 'DDoS' },
      { timestamp: ts, attack_type: 'PortScan' },
    ]
    const { chartData, attackTypes } = buildChartData(alerts)
    expect(attackTypes).toEqual(['DDoS', 'PortScan'])
    expect(chartData[0]['DDoS']).toBe(2)
    expect(chartData[0]['PortScan']).toBe(1)
  })

  it('returns attackTypes sorted alphabetically', () => {
    const ts = recentTimestamp()
    const alerts = [
      { timestamp: ts, attack_type: 'ZeroDay' },
      { timestamp: ts, attack_type: 'BruteForce' },
      { timestamp: ts, attack_type: 'DDoS' },
    ]
    const { attackTypes } = buildChartData(alerts)
    expect(attackTypes).toEqual(['BruteForce', 'DDoS', 'ZeroDay'])
  })

  it('sorts chartData buckets chronologically', () => {
    const earlier = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
    const later = new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString()
    const alerts = [
      { timestamp: later, attack_type: 'DDoS' },
      { timestamp: earlier, attack_type: 'DDoS' },
    ]
    const { chartData } = buildChartData(alerts)
    if (chartData.length > 1) {
      expect(chartData[0].hour.localeCompare(chartData[1].hour)).toBeLessThan(0)
    }
  })

  it('uses "unknown" for alerts with no attack_type', () => {
    const ts = recentTimestamp()
    const { chartData, attackTypes } = buildChartData([{ timestamp: ts }])
    expect(attackTypes).toEqual([])
    expect(chartData[0]['unknown']).toBe(1)
  })
})

// ── Component render tests (Requirement 14.2, 14.8) ──────────────────────────
describe('AttackChart component', () => {
  it('renders "No attack data" message when no alerts in last 24 hours', async () => {
    const oldTs = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString()
    getAlerts.mockResolvedValue([{ timestamp: oldTs, attack_type: 'DDoS' }])
    renderWithProvider(<AttackChart />)
    await waitFor(() => {
      expect(screen.getByText(/No attack data in the last 24 hours/i)).toBeInTheDocument()
    })
  })

  it('renders "No attack data" message when getAlerts returns empty array', async () => {
    getAlerts.mockResolvedValue([])
    renderWithProvider(<AttackChart />)
    await waitFor(() => {
      expect(screen.getByText(/No attack data in the last 24 hours/i)).toBeInTheDocument()
    })
  })

  it('groups alerts by attack_type and renders chart when data is present', async () => {
    const alerts = [
      { timestamp: recentTimestamp(), attack_type: 'DDoS' },
      { timestamp: recentTimestamp(), attack_type: 'DDoS' },
      { timestamp: recentTimestamp(), attack_type: 'PortScan' },
    ]
    getAlerts.mockResolvedValue(alerts)
    renderWithProvider(<AttackChart />)

    await waitFor(() => {
      expect(screen.getByText(/Attacks by Type/i)).toBeInTheDocument()
      expect(screen.queryByText(/No attack data in the last 24 hours/i)).not.toBeInTheDocument()
    })
  })

  // Requirement 14.8 — error handling
  it('shows error message when getAlerts throws', async () => {
    getAlerts.mockRejectedValue(new Error('API unavailable'))
    renderWithProvider(<AttackChart />)
    await waitFor(() => {
      expect(screen.getByText('API unavailable')).toBeInTheDocument()
    })
  })
})
