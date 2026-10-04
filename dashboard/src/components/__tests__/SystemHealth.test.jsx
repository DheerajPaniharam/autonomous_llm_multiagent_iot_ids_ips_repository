import React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import SystemHealth from '../SystemHealth'
import { DashboardProvider } from '../../contexts/DashboardContext'

vi.mock('../../services/api', () => ({
  getMetrics: vi.fn(),
  getAlerts: vi.fn(),
  getLiveTraffic: vi.fn(),
  getHealth: vi.fn(),
  getIncidents: vi.fn(),
}))

vi.mock('../../services/ws', () => ({
  subscribe: vi.fn(() => () => {}),
}))

vi.mock('../../utils/auth', () => ({
  isAuthenticated: vi.fn(() => true),
}))

import { getMetrics, getAlerts, getLiveTraffic, getHealth, getIncidents } from '../../services/api'

beforeEach(() => {
  vi.clearAllMocks()
  getMetrics.mockResolvedValue({})
  getAlerts.mockResolvedValue([])
  getLiveTraffic.mockResolvedValue([])
  getIncidents.mockResolvedValue([])
})

const healthyData = {
  status: 'healthy',
  database: 'ok',
  ml_models: { supervised: 'ok', if: 'ok' },
  ollama: 'ok',
  agents: {},
}

describe('SystemHealth', () => {
  // Requirement 14.4 — overall status badge
  it('shows "healthy" status badge when health data is good', async () => {
    getHealth.mockResolvedValue(healthyData)
    render(
      <DashboardProvider>
        <SystemHealth />
      </DashboardProvider>
    )
    await waitFor(() => {
      expect(screen.getByText('HEALTHY')).toBeInTheDocument()
    })
  })

  it('shows "degraded" status badge when database is down', async () => {
    getHealth.mockResolvedValue({
      status: 'degraded',
      database: { status: 'error', reason: 'connection timeout' },
      ml_models: { supervised: 'ok' },
      ollama: 'ok',
      agents: {},
    })
    render(
      <DashboardProvider>
        <SystemHealth />
      </DashboardProvider>
    )
    await waitFor(() => {
      expect(screen.getByText('DEGRADED')).toBeInTheDocument()
    })
  })

  // Requirement 14.4 — green indicator for healthy components
  it('shows green indicator (aria-label "ok") for healthy components', async () => {
    getHealth.mockResolvedValue(healthyData)
    render(
      <DashboardProvider>
        <SystemHealth />
      </DashboardProvider>
    )
    await waitFor(() => {
      const okDots = screen.getAllByLabelText('ok')
      expect(okDots.length).toBeGreaterThan(0)
    })
  })

  // Requirement 14.4 — red indicator for error components
  it('shows red indicator (aria-label "error") for error components', async () => {
    getHealth.mockResolvedValue({
      status: 'degraded',
      database: { status: 'error', reason: 'down' },
      ml_models: {},
      ollama: 'ok',
      agents: {},
    })
    render(
      <DashboardProvider>
        <SystemHealth />
      </DashboardProvider>
    )
    await waitFor(() => {
      const errorDots = screen.getAllByLabelText('error')
      expect(errorDots.length).toBeGreaterThan(0)
    })
  })

  // Requirement 14.4 — merged five-agent display
  it('displays all five merged agent pipeline statuses even when legacy agent keys are returned', async () => {
    getHealth.mockResolvedValue({
      status: 'healthy',
      database: 'ok',
      ml_models: {},
      ollama: 'ok',
      agents: {
        traffic: true,
        detection: true,
        anomaly: true,
        risk: true,
        orchestrator: true,
        prevention: true,
        healing: true,
        logging: true,
        reporting: true,
      },
    })
    render(
      <DashboardProvider>
        <SystemHealth />
      </DashboardProvider>
    )
    await waitFor(() => {
      expect(screen.getByText('Agent (traffic)')).toBeInTheDocument()
      expect(screen.getByText('Agent (analysis)')).toBeInTheDocument()
      expect(screen.getByText('Agent (orchestrator)')).toBeInTheDocument()
      expect(screen.getByText('Agent (response)')).toBeInTheDocument()
      expect(screen.getByText('Agent (observability)')).toBeInTheDocument()
    })
  })

  it('shows red indicator for a failed agent', async () => {
    getHealth.mockResolvedValue({
      status: 'degraded',
      database: 'ok',
      ml_models: {},
      ollama: 'ok',
      agents: { detection: false },
    })
    render(
      <DashboardProvider>
        <SystemHealth />
      </DashboardProvider>
    )
    await waitFor(() => {
      // The failed agent dot should have aria-label "error"
      const errorDots = screen.getAllByLabelText('error')
      expect(errorDots.length).toBeGreaterThan(0)
    })
  })

  // Requirement 14.4 — ml_models sub-keys displayed
  it('displays LightGBM and IF model statuses from ml_models field', async () => {
    getHealth.mockResolvedValue({
      status: 'healthy',
      database: 'ok',
      ml_models: { supervised: 'ok', if: 'ok' },
      ollama: 'ok',
      agents: {},
    })
    render(
      <DashboardProvider>
        <SystemHealth />
      </DashboardProvider>
    )
    await waitFor(() => {
      expect(screen.getByText('ML Model (LightGBM)')).toBeInTheDocument()
      expect(screen.getByText('ML Model (IF)')).toBeInTheDocument()
      expect(screen.queryByText('ML Model (SUPERVISED)')).not.toBeInTheDocument()
    })
  })

  // Requirement 14.4 — ollama status
  it('shows red indicator when ollama is unavailable', async () => {
    getHealth.mockResolvedValue({
      status: 'degraded',
      database: 'ok',
      ml_models: {},
      ollama: 'unavailable',
      agents: {},
    })
    render(
      <DashboardProvider>
        <SystemHealth />
      </DashboardProvider>
    )
    await waitFor(() => {
      const errorDots = screen.getAllByLabelText('error')
      expect(errorDots.length).toBeGreaterThan(0)
    })
  })

  // Requirement 14.8 — error handling
  it('shows error message when getHealth throws', async () => {
    getHealth.mockRejectedValue(new Error('Health check failed'))
    render(
      <DashboardProvider>
        <SystemHealth />
      </DashboardProvider>
    )
    await waitFor(() => {
      expect(screen.getByText('Health check failed')).toBeInTheDocument()
    })
  })
})
