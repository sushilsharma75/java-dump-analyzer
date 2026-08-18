/**
 * Minimal block-level markdown parser shared by the on-screen AI panel and the
 * exported report, so both render a diagnosis identically.
 *
 * Returns a flat list of blocks:
 *   { type: 'heading', level, text }
 *   { type: 'code', text }
 *   { type: 'ul' | 'ol', items: string[] }
 *   { type: 'paragraph', text }
 *
 * Inline `**bold**` and `` `code` `` are left in the text for the renderer to
 * handle — see parseInline.
 */
export function parseMarkdown(text) {
  const lines = String(text || '').split('\n')
  const blocks = []
  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    const stripped = line.trim()

    if (!stripped) { i++; continue }

    // Fenced code block: ```lang ... ```
    if (/^```/.test(stripped)) {
      i++  // skip opening fence
      const code = []
      while (i < lines.length && !/^```/.test(lines[i].trim())) {
        code.push(lines[i])
        i++
      }
      if (i < lines.length) i++  // skip closing fence
      blocks.push({ type: 'code', text: code.join('\n') })
      continue
    }

    // Headings
    const h = /^(#{1,6})\s+(.*)$/.exec(stripped)
    if (h) {
      blocks.push({ type: 'heading', level: h[1].length, text: h[2] })
      i++; continue
    }

    // Unordered list
    if (/^[-*+]\s+/.test(stripped)) {
      const items = []
      while (i < lines.length && /^[-*+]\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^[-*+]\s+/, ''))
        i++
      }
      blocks.push({ type: 'ul', items })
      continue
    }

    // Ordered list
    if (/^\d+[.)]\s+/.test(stripped)) {
      const items = []
      while (i < lines.length && /^\d+[.)]\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^\d+[.)]\s+/, ''))
        i++
      }
      blocks.push({ type: 'ol', items })
      continue
    }

    // Paragraph: gather contiguous non-empty lines
    const para = []
    while (i < lines.length && lines[i].trim() && !/^(#{1,6}\s|[-*+]\s|\d+[.)]\s)/.test(lines[i].trim())) {
      para.push(lines[i].trim())
      i++
    }
    if (para.length) blocks.push({ type: 'paragraph', text: para.join(' ') })
  }
  return blocks
}

/**
 * Split a line into { kind: 'text' | 'bold' | 'code', text } runs.
 */
export function parseInline(text) {
  const src = String(text || '')
  const parts = []
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g
  let lastIdx = 0
  let m
  while ((m = re.exec(src)) !== null) {
    if (m.index > lastIdx) parts.push({ kind: 'text', text: src.slice(lastIdx, m.index) })
    if (m[0].startsWith('**')) {
      parts.push({ kind: 'bold', text: m[0].slice(2, -2) })
    } else {
      parts.push({ kind: 'code', text: m[0].slice(1, -1) })
    }
    lastIdx = m.index + m[0].length
  }
  if (lastIdx < src.length) parts.push({ kind: 'text', text: src.slice(lastIdx) })
  return parts
}
