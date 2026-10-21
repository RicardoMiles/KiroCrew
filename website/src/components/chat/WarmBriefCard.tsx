/**
 * WarmBriefCard — the catch-up a crewmate posts when the owner returns to an
 * active thread (`meta.kind === 'warm_task_brief_result'`).
 *
 * The gateway validates the model's JSON into `meta.brief` (`asked`, `now`,
 * `needs_you[]`, `next[]`) and this card draws it in a FIXED layout. Every
 * field is untrusted model output grounded in an untrusted snapshot, so each
 * one is drawn as a plain React text node: never markdown, never HTML, never a
 * link or a button. A row without a valid `meta.brief` (an older prose brief)
 * is not claimed here and keeps its ordinary bubble.
 */
import { i18nT } from '../../i18n/t'
import type { ChatMessage } from '../../types'

export interface WarmBrief {
  asked: string
  now: string
  needsYou: string[]
  next: string[]
}

// The gateway caps every field already; these are the renderer's own bound so
// a hand-edited or foreign row can never stretch the card.
const MAX_FIELD = 240
const MAX_ITEMS = 3

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim().slice(0, MAX_FIELD) : ''
}

function items(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.map(text).filter(Boolean).slice(0, MAX_ITEMS)
}

/** The row's validated brief, or null when this row is not a structured brief. */
export function warmBriefOf(m: ChatMessage): WarmBrief | null {
  const meta = m.meta as { kind?: unknown; brief?: unknown } | undefined
  if (meta?.kind !== 'warm_task_brief_result') return null
  const raw = meta.brief
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const b = raw as Record<string, unknown>
  const now = text(b.now)
  if (!now) return null
  return { asked: text(b.asked), now, needsYou: items(b.needs_you), next: items(b.next) }
}

const SECTION_LABEL = 'text-[11px] leading-4 font-semibold mb-0.5'

export default function WarmBriefCard({ brief, className = '' }: { brief: WarmBrief; className?: string }) {
  return (
    <div
      className={`message-bubble text-text leading-relaxed min-w-0 flex flex-col gap-2 ${className}`}
      style={{ overflowWrap: 'anywhere', fontSize: 'var(--mc-message-font-size, 14px)' }}
      data-testid="warm-brief-card"
      role="group"
      aria-label={i18nT('components.warmBriefCard.label')}
    >
      {brief.asked && (
        <div className="text-[12px] leading-4 text-muted" data-testid="warm-brief-asked">
          {i18nT('components.warmBriefCard.asked')}: {brief.asked}
        </div>
      )}
      <div className="font-semibold text-text-strong" data-testid="warm-brief-now">{brief.now}</div>
      {brief.needsYou.length > 0 && (
        <div className="rounded-lg bg-warn-subtle text-text px-2.5 py-1.5 forced-colors:border" data-testid="warm-brief-needs-you">
          <div className={`${SECTION_LABEL} text-warn-text`}>{i18nT('components.warmBriefCard.needs_you')}</div>
          <ul className="m-0 pl-4 list-disc">
            {brief.needsYou.map((item, i) => <li key={i}>{item}</li>)}
          </ul>
        </div>
      )}
      {brief.next.length > 0 && (
        <div data-testid="warm-brief-next">
          <div className={`${SECTION_LABEL} text-muted`}>{i18nT('components.warmBriefCard.next')}</div>
          <ol className="m-0 pl-5 list-decimal">
            {brief.next.map((item, i) => <li key={i}>{item}</li>)}
          </ol>
        </div>
      )}
    </div>
  )
}
