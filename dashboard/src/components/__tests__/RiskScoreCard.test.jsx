import React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import RiskScoreCard from '../RiskScoreCard'
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

import { getAlerts, getMetrics, getLiveTraffic, getHealth, getIncidents } from '../../services/api'

beforeEach(() => {
  vi.clearAllMocks()
  getMetrics.mockResolvedValue({})
  getAlerts.mockResolvedValue([])
  getLiveTraffic.mockResolvedValue([])
  getHealth.mockResolvedValue({ status: 'healthy', database: 'ok', ml_models: {}, ollama: 'ok', agents: {} })
  getIncidents.mockResolvedValue([])
})

// Timestamp within the last 5 minutes
const recentTs = () => new Date(Date.now() - 30 * 1000).toISOString()

describe('RiskScoreCard', () => {
  // Requirement 14.3 — no recent data
  it('shows "No recent threats" when no alerts in last 5 minutes', async () => {
    const oldTs = new Date(Date.now() - 10 * 60 * 1000).toISOString()
    getAlerts.mockResolvedValue([{ timestamp: oldTs, composite_score: 0.95 }])
    renderWithProvider(<RiskScoreCard />)
    await waitFor(() => {
      expect(screen.getByText('No recent threats')).toBeInTheDocument()
    })
  })

  it('shows "No recent threats" when getAlerts returns empty array', async () => {
    getAlerts.mockResolvedValue([])
    renderWithProvider(<RiskScoreCard />)
    await waitFor(() => {
      expect(screen.getByText('No recent threats')).toBeInTheDocument()
    })
  })

  // Requirement 14.3 — colour coding: red >= 0.9
  it('shows score with CRITICAL label for score >= 0.9', async () => {
    getAlerts.mockResolvedValue([{ timestamp: recentTs(), composite_score: 0.95 }])
    renderWithProvider(<RiskScoreCard />)
    await waitFor(() => {
      expect(screen.getByText('0.95')).toBeInTheDocument()
      expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    })
  })

  it('shows CRITICAL label at exact boundary score of 0.9', async () => {
    getAlerts.mockResolvedValue([{ timestamp: recentTs(), composite_score: 0.9 }])
    renderWithProvider(<RiskScoreCard />)
    await waitFor(() => {
      expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    })
  })

  // Requirement 14.3 — colour coding: amber 0.65–0.89
  it('shows score with ELEVATED label for score between 0.65 and 0.89', async () => {
    getAlerts.mockResolvedValue([{ timestamp: recentTs(), composite_score: 0.75 }])
    renderWithProvider(<RiskScoreCard />)
    await waitFor(() => {
      expect(screen.getByText('0.75')).toBeInTheDocument()
      expect(screen.getByText('ELEVATED')).toBeInTheDocument()
    })
  })

  it('shows ELEVATED label at exact lower boundary score of 0.65', async () => {
    getAlerts.mockResolvedValue([{ timestamp: recentTs(), composite_score: 0.65 }])
    renderWithProvider(<RiskScoreCard />)
    await waitFor(() => {
      expect(screen.getByText('ELEVATED')).toBeInTheDocument()
    })
  })

  it('shows ELEVATED label at upper boundary score of 0.89', async () => {
    getAlerts.mockResolvedValue([{ timestamp: recentTs(), composite_score: 0.89 }])
    renderWithProvider(<RiskScoreCard />)
    await waitFor(() => {
      expect(screen.getByText('ELEVATED')).toBeInTheDocument()
    })
  })

  // Requirement 14.3 — colour coding: green < 0.65
  it('shows score with NORMAL label for score < 0.65', async () => {
    getAlerts.mockResolvedValue([{ timestamp: recentTs(), composite_score: 0.40 }])
    renderWithProvider(<RiskScoreCard />)
    await waitFor(() => {
      expect(screen.getByText('0.40')).toBeInTheDocument()
      expect(screen.getByText('NORMAL')).toBeInTheDocument()
    })
  })

  it('shows NORMAL label at score just below 0.65 (0.64)', async () => {
    getAlerts.mockResolvedValue([{ timestamp: recentTs(), composite_score: 0.64 }])
    renderWithProvider(<RiskScoreCard />)
    await waitFor(() => {
      expect(screen.getByText('NORMAL')).toBeInTheDocument()
    })
  })

  // Requirement 14.3 — picks highest score from multiple recent alerts
  it('displays the highest composite score when multiple recent alerts exist', async () => {
    getAlerts.mockResolvedValue([
      { timestamp: recentTs(), composite_score: 0.50 },
      { timestamp: recentTs(), composite_score: 0.92 },
      { timestamp: recentTs(), composite_score: 0.70 },
    ])
    renderWithProvider(<RiskScoreCard />)
    await waitFor(() => {
      expect(screen.getByText('0.92')).toBeInTheDocument()
      expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    })
  })

  // Requirement 14.8 — error handling
  it('shows error message when getAlerts throws', async () => {
    getAlerts.mockRejectedValue(new Error('Connection refused'))
    renderWithProvider(<RiskScoreCard />)
    await waitFor(() => {
      expect(screen.getByText('Connection refused')).toBeInTheDocument()
    })
  })
})
