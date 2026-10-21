import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { defaultMessageRenderers, mergeRenderers, resolveRenderer } from '../app-sdk/messageRenderers'
import { isCrewmateChatRow } from '../components/chat/crewmateBubbles'
import WarmBriefCard, { warmBriefOf } from '../components/chat/WarmBriefCard'
import type { ChatMessage } from '../types'

const row = (role: ChatMessage['role'], meta: Record<string, unknown>, content = ''): ChatMessage => ({
  role, content, cls: role === 'assistant' ? 'msg msg-a' : '', meta,
})

const brief = (fields: Record<string, unknown>) =>
  row('assistant', { kind: 'warm_task_brief_result', fingerprint: 'fp', brief: fields }, 'You asked: x\nNow: y')

describe('warm task brief transcript rows', () => {
  it('hides only the durable claim', () => {
    const claim = row('notice', { kind: 'warm_task_brief_claim', fingerprint: 'abc' })
    const renderer = defaultMessageRenderers.find(item => item.id === 'warm_task_brief_claim')!
    expect(renderer.match?.(claim)).toBe(true)
    expect(renderer.render(claim, {} as never)).toBeNull()
    expect(isCrewmateChatRow(claim)).toBe(false)
  })

  it('keeps preparing rows and old prose briefs on the ordinary bubble', () => {
    const preparing = row('assistant', { kind: 'warm_task_brief_preparing' }, 'Welcome back, let me catch you up on where we are.')
    const prose = row('assistant', { kind: 'warm_task_brief_result' }, 'You asked me to fix the test. It is ready now.')
    expect(isCrewmateChatRow(preparing)).toBe(true)
    expect(isCrewmateChatRow(prose)).toBe(true)
    expect(warmBriefOf(prose)).toBeNull()
    expect(resolveRenderer(prose, defaultMessageRenderers)?.id).toBe('assistant')
    expect(resolveRenderer(preparing, defaultMessageRenderers)?.id).toBe('assistant')
  })

  it('draws a structured brief as the card, ahead of any host assistant bubble', () => {
    const m = brief({ asked: 'Fix the test', now: 'Ready.', needs_you: [], next: ['Review'] })
    expect(isCrewmateChatRow(m)).toBe(true)
    // No host renderers (ChatEmbed): the defaults alone must pick the card.
    expect(resolveRenderer(m, mergeRenderers(undefined))?.id).toBe('warm_task_brief_result')
    const host = [{ id: 'assistant', roles: ['assistant'], render: () => null }] as const
    expect(resolveRenderer(m, mergeRenderers(host as never))?.id).toBe('warm_task_brief_result')
  })

  it.each([
    ['missing brief', undefined],
    ['brief is a list', ['now']],
    ['brief is text', 'now'],
    ['empty now', { now: '  ', asked: 'x' }],
    ['now not a string', { now: 3 }],
  ])('refuses a malformed brief (%s)', (_label, fields) => {
    expect(warmBriefOf(brief(fields as Record<string, unknown>))).toBeNull()
  })

  it('caps fields and items and drops non-strings', () => {
    const b = warmBriefOf(brief({
      asked: 'a'.repeat(900), now: 'n', needs_you: ['x', 2, '', null, 'y', 'z', 'w'], next: 'not a list',
    }))!
    expect(b.asked.length).toBe(240)
    expect(b.needsYou).toEqual(['x', 'y', 'z'])
    expect(b.next).toEqual([])
  })
})

describe('WarmBriefCard', () => {
  it('shows every section and leaves out an empty needs-you', () => {
    const { rerender } = render(<WarmBriefCard brief={{ asked: 'Fix the test', now: 'PR is open.', needsYou: ['Approve the push'], next: ['Review', 'Merge'] }} />)
    expect(screen.getByTestId('warm-brief-asked')).toHaveTextContent('Fix the test')
    expect(screen.getByTestId('warm-brief-now')).toHaveTextContent('PR is open.')
    expect(screen.getByTestId('warm-brief-needs-you')).toHaveTextContent('Approve the push')
    expect(screen.getByTestId('warm-brief-next').querySelectorAll('li')).toHaveLength(2)
    rerender(<WarmBriefCard brief={{ asked: '', now: 'PR is open.', needsYou: [], next: [] }} />)
    expect(screen.queryByTestId('warm-brief-needs-you')).toBeNull()
    expect(screen.queryByTestId('warm-brief-next')).toBeNull()
    expect(screen.queryByTestId('warm-brief-asked')).toBeNull()
  })

  it('draws markup, links and fake buttons as plain text', () => {
    const { container } = render(<WarmBriefCard brief={{
      asked: '<img src=x onerror=alert(1)>',
      now: '[Click here](https://evil.example) **now**',
      needsYou: ['<button>Approve</button>'],
      next: ['https://evil.example/run'],
    }} />)
    expect(container.querySelector('a, button, img, strong, script')).toBeNull()
    expect(screen.getByTestId('warm-brief-now').textContent).toBe('[Click here](https://evil.example) **now**')
    expect(screen.getByTestId('warm-brief-needs-you')).toHaveTextContent('<button>Approve</button>')
  })

  it('renders Chinese text as given', () => {
    render(<WarmBriefCard brief={{ asked: '修复测试', now: '已经复现了失败。', needsYou: ['批准推送'], next: ['应用修复'] }} />)
    expect(screen.getByTestId('warm-brief-now')).toHaveTextContent('已经复现了失败。')
    expect(screen.getByTestId('warm-brief-needs-you')).toHaveTextContent('批准推送')
  })

  it('a reloaded row (same meta) renders the same card', () => {
    const m = brief({ asked: 'Fix', now: 'Ready.', needs_you: ['Approve'], next: ['Merge'] })
    const reloaded = JSON.parse(JSON.stringify(m)) as ChatMessage
    const first = render(<WarmBriefCard brief={warmBriefOf(m)!} />).container.innerHTML
    const second = render(<WarmBriefCard brief={warmBriefOf(reloaded)!} />).container.innerHTML
    expect(second).toBe(first)
  })
})

describe("the card in a crewmate's chat", () => {
  it('sits in the run as a filled crewmate bubble', async () => {
    const { createTranscriptRenderers } = await import('../pages/chat/transcriptRenderers')
    const m = brief({ asked: 'Fix', now: 'Ready.', needs_you: [], next: ['Merge'] })
    const renderers = mergeRenderers(createTranscriptRenderers({
      slot: 'member-radar', crewmate: { name: 'Radar' }, crewmateTranscript: () => [m],
    }))
    const entry = resolveRenderer(m, renderers)
    expect(entry?.id).toBe('warm_task_brief_result')
    const ctx = {
      index: 0, messages: [m], running: false, key: 'k0', hideCardOwnedOAuth: false,
      autoDeniedIds: new Set<string>(), wrapper: (c: unknown) => c, row: (c: unknown) => c,
    }
    render(<>{entry!.render(m, ctx as never)}</>)
    const card = screen.getByTestId('warm-brief-card')
    expect(card.className).toContain('crewmate-bubble')
    expect(card.className).toContain('message-bubble')
  })
})
