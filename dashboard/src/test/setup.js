import '@testing-library/jest-dom'

// Mock ResizeObserver for recharts (SVG/canvas not supported in jsdom)
globalThis.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
