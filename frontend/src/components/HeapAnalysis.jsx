import { useState } from 'react'
import Findings from './Findings'
import LLMPanel from './LLMPanel'
import VerdictBanner from './VerdictBanner'
import ExportReport from './ExportReport'
import { fmtBytes } from '../report'

function fmtTimestamp(ms) {
  if (!ms) return null
  try {
    return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')
  } catch {
    return null
  }
}

// Every ranked table shows this many rows before asking. A heap dump has tens of
// thousands of classes; the top few are the investigation, the rest are noise.
export const TOP_N = 10

export default function HeapAnalysis({ analysis, filename }) {
  return (
    <div className="max-w-7xl mx-auto pt-8 space-y-8">
      <VerdictBanner verdict={analysis.verdict} summary={analysis.summary} />
      <Coverage analysis={analysis} />
      <CaseFile analysis={analysis} filename={filename} />
      <Stats analysis={analysis} />
      <ExportReport analysis={analysis} filename={filename} kind="heap" />

      <Section label="// diagnostic findings" count={analysis.findings.length}>
        <Findings findings={analysis.findings} />
      </Section>

      {analysis.dominators?.length > 0 && (
        <Section
          label={`// dominator tree · top ${Math.min(TOP_N, analysis.dominators.length)} objects by retained size`}
          count={analysis.dominators.length}
        >
          <Dominators analysis={analysis} />
        </Section>
      )}

      {analysis.deployments?.length > 0 && (
        <Section label="// deployments · classloaders & artifacts" count={analysis.deployments.length}>
          <Deployments
            deployments={analysis.deployments}
            ownership={analysis.thread_ownership}
          />
        </Section>
      )}

      {analysis.duplicate_classes?.length > 0 && (
        <Section label="// duplicate classes · same class, multiple classloaders" count={analysis.duplicate_classes.length}>
          <DuplicateClasses entries={analysis.duplicate_classes} />
        </Section>
      )}

      <LLMPanel analysis={analysis} kind="heap" />

      <Section
        label={`// histogram · top ${TOP_N} classes by shallow size`}
        count={analysis.top_classes_by_size?.length}
      >
        <Histogram entries={analysis.top_classes_by_size} sortKey="shallow_size_bytes" />
      </Section>

      <Section
        label={`// histogram · top ${TOP_N} classes by instance count`}
        count={analysis.top_classes_by_count?.length}
      >
        <Histogram entries={analysis.top_classes_by_count} sortKey="instance_count" />
      </Section>

      <Section label="// record types in this dump" count={Object.keys(analysis.record_type_counts || {}).length}>
        <RecordTypes counts={analysis.record_type_counts} />
      </Section>
    </div>
  )
}

/**
 * What this analysis actually covers. A dump parsed in quick mode, or one too big
 * for the dominator pass, produces a page that looks identical to a complete
 * analysis — this banner is what stops that from misleading the reader.
 */
function Coverage({ analysis }) {
  const skipped = analysis.skipped_analyses || []
  if (!analysis.truncated && skipped.length === 0) return null

  return (
    <div
      className={`panel p-5 animate-fade-in ${
        analysis.truncated
          ? 'border-flag-warning/40 bg-flag-warning/[0.04]'
          : 'border-flag-info/30 bg-flag-info/[0.03]'
      }`}
    >
      <div className="flex items-start gap-3">
        <span className={`font-mono shrink-0 ${analysis.truncated ? 'text-flag-warning' : 'text-flag-info'}`}>
          {analysis.truncated ? '◑' : 'ⓘ'}
        </span>
        <div className="flex-1 min-w-0 space-y-2">
          {analysis.truncated && (
            <p className="text-sm text-bone-100 leading-relaxed">
              <span className="font-medium">Partial analysis.</span>{' '}
              Only {fmtBytes(analysis.analyzed_bytes)} of this{' '}
              {fmtBytes(analysis.file_size_bytes)} dump was read (quick mode). Every count
              and percentage below describes that prefix — not the whole heap.
            </p>
          )}
          {skipped.length > 0 && (
            <>
              <div className="label text-bone-400">stages that did not run</div>
              <ul className="space-y-1">
                {skipped.map((s, i) => (
                  <li key={i} className="text-[13px] text-bone-300 leading-snug">
                    <span className="font-mono text-bone-200">{s.stage}</span>
                    <span className="text-bone-500"> — {s.reason}</span>
                    {s.enable_hint && (
                      <span className="text-bone-500"> · {s.enable_hint}</span>
                    )}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function CaseFile({ analysis, filename }) {
  const ts = fmtTimestamp(analysis.timestamp_ms)
  return (
    <div className="panel p-6 animate-fade-in">
      <div className="flex flex-wrap items-baseline gap-x-6 gap-y-2 text-sm">
        <div>
          <span className="label">case file</span>
          <div className="font-mono text-bone-200 mt-1">{filename || '<upload>'}</div>
        </div>
        {ts && (
          <div>
            <span className="label">captured</span>
            <div className="font-mono text-bone-200 mt-1">{ts}</div>
          </div>
        )}
        <div>
          <span className="label">format</span>
          <div className="font-mono text-bone-200 mt-1">{analysis.header || 'hprof'}</div>
        </div>
        <div>
          <span className="label">id size</span>
          <div className="font-mono text-bone-200 mt-1">{analysis.identifier_size}b</div>
        </div>
      </div>
    </div>
  )
}

function Summary({ analysis }) {
  return (
    <div className="panel p-6 md:p-8 animate-slide-up">
      <div className="label mb-3">// triage summary</div>
      <p className="text-bone-100 text-lg md:text-xl font-light leading-relaxed font-display tracking-tight">
        {analysis.summary}
      </p>
    </div>
  )
}

function Stats({ analysis }) {
  const wasted = analysis.wasted_bytes_estimate
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 animate-slide-up">
      <Stat label="file size" value={fmtBytes(analysis.file_size_bytes)} />
      <Stat label="instances" value={analysis.total_instances?.toLocaleString() ?? '—'} />
      <Stat label="classes loaded" value={analysis.total_classes_loaded?.toLocaleString() ?? '—'} />
      <Stat label="findings" value={analysis.findings.length} />
      {wasted > 0 && (
        <Stat label="reclaimable (dupes)" value={fmtBytes(wasted)} critical />
      )}
    </div>
  )
}

function Stat({ label, value, critical }) {
  return (
    <div className={`panel p-5 ${critical ? 'border-flag-critical/40 bg-flag-critical/[0.03]' : ''}`}>
      <div className="label mb-2">{label}</div>
      <div className={`stat-num ${critical ? 'text-flag-critical' : ''}`}>{value}</div>
    </div>
  )
}

function Section({ label, count, children }) {
  return (
    <section className="animate-slide-up">
      <div className="flex items-center justify-between mb-4">
        <div className="label text-bone-300">{label}</div>
        {count != null && <span className="badge-neutral">{count}</span>}
      </div>
      {children}
    </section>
  )
}

/**
 * Footer for a capped table: says what is hidden and reveals it on demand.
 * Every ranked list on this page is cut to TOP_N, so the count has to be visible
 * — a silently truncated table reads as a complete one.
 */
function ShowMore({ shown, total, onMore, onLess }) {
  if (total <= shown && shown <= TOP_N) return null
  return (
    <div className="px-5 py-3 border-t border-ink-600/60 flex items-center gap-4">
      {total > shown && (
        <button
          onClick={onMore}
          className="font-mono text-xs text-bone-400 hover:text-bone-200 transition-colors"
        >
          → show more ({total - shown} remaining)
        </button>
      )}
      {shown > TOP_N && (
        <button
          onClick={onLess}
          className="font-mono text-xs text-bone-500 hover:text-bone-300 transition-colors"
        >
          ↑ back to top {TOP_N}
        </button>
      )}
      <span className="font-mono text-xs text-bone-500 ml-auto">
        showing {shown} of {total}
      </span>
    </div>
  )
}

function Histogram({ entries, sortKey }) {
  const [limit, setLimit] = useState(TOP_N)
  const [expanded, setExpanded] = useState({})
  if (!entries?.length) {
    return <div className="panel p-5 text-bone-500 font-mono text-sm">no entries</div>
  }
  const max = Math.max(...entries.map(e => e[sortKey]))
  const visible = entries.slice(0, limit)

  return (
    <div className="panel overflow-hidden">
      <div className="grid grid-cols-[1fr_auto_auto] gap-x-4 px-5 py-3 border-b border-ink-600/60 label">
        <span>class</span>
        <span className="text-right">instances</span>
        <span className="text-right w-24">shallow size</span>
      </div>
      <div>
        {visible.map((e, i) => {
          const pct = max > 0 ? (e[sortKey] / max) * 100 : 0
          const hasRefs = e.references && e.references.length > 0
          const isOpen = expanded[i]
          return (
            <div key={i} className="border-b border-ink-700/30 last:border-0">
              <div
                className={`grid grid-cols-[1fr_auto_auto] gap-x-4 px-5 py-2.5 items-center text-sm relative ${hasRefs ? 'cursor-pointer' : ''}`}
                onClick={hasRefs ? () => setExpanded(s => ({ ...s, [i]: !s[i] })) : undefined}
              >
                <div className="absolute inset-y-0 left-0 bg-flag-info/[0.06]" style={{ width: `${pct}%` }} />
                <span className="min-w-0 relative z-10">
                  <span className="font-mono text-xs text-bone-200 truncate block">
                    {hasRefs && (
                      <span className={`text-flag-ok mr-1.5 inline-block transition-transform ${isOpen ? 'rotate-90' : ''}`}>▸</span>
                    )}
                    {e.class_name}
                    {e.pct_of_total_size != null && e.pct_of_total_size >= 1 && (
                      <span className="text-bone-500 ml-2">{e.pct_of_total_size}% of heap</span>
                    )}
                    {hasRefs && (
                      <span className="badge-ok ml-2">{e.references.length} in your code</span>
                    )}
                  </span>
                  {e.explanation && (
                    <span className="text-[11px] text-bone-500 leading-snug block truncate" title={e.explanation}>
                      {e.explanation}
                    </span>
                  )}
                </span>
                <span className="font-mono text-xs text-bone-300 text-right tabular-nums relative z-10">
                  {e.instance_count.toLocaleString()}
                </span>
                <span className="font-mono text-xs text-bone-100 text-right tabular-nums w-24 relative z-10">
                  {fmtBytes(e.shallow_size_bytes)}
                </span>
              </div>
              {hasRefs && isOpen && (
                <div className="px-5 pb-3 pl-11 space-y-2 animate-fade-in">
                  <div className="label text-bone-400 pt-1">
                    where your code references this class
                  </div>
                  {e.references.map((ref, j) => (
                    <ClassRef key={j} r={ref} />
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
      <ShowMore
        shown={visible.length}
        total={entries.length}
        onMore={() => setLimit(l => l + TOP_N)}
        onLess={() => setLimit(TOP_N)}
      />
    </div>
  )
}

const REF_KIND_LABEL = {
  new: 'constructed',
  field: 'field',
  'type-use': 'used',
  import: 'import',
}

function ClassRef({ r }) {
  const kindBadge = r.kind === 'new' ? 'badge-warning' : 'badge-neutral'
  return (
    <div className="panel-inset overflow-hidden">
      <div className="px-3 py-2 border-b border-ink-600/40 flex items-center gap-2 flex-wrap bg-ink-950/40">
        <span className={kindBadge}>{REF_KIND_LABEL[r.kind] || r.kind}</span>
        <span className="font-mono text-[11px] text-bone-200 truncate">
          {r.repo_path}<span className="text-bone-500">:{r.line}</span>
        </span>
        {r.method && (
          <span className="font-mono text-[11px] text-flag-ok ml-auto">
            in {r.method}()
          </span>
        )}
      </div>
      {r.snippet && r.snippet.lines.length > 0 && (
        <div className="font-mono text-[11px] leading-relaxed overflow-x-auto">
          <pre className="p-0 m-0">
            {r.snippet.lines.map((line, k) => {
              const ln = r.snippet.start_line + k
              const hl = ln === r.snippet.highlight_line
              return (
                <div key={k} className={`flex ${hl ? 'bg-flag-warning/10' : ''}`}>
                  <span className={`select-none px-3 py-0.5 text-right shrink-0 w-12 tabular-nums ${hl ? 'text-flag-warning' : 'text-bone-500'}`}>{ln}</span>
                  <span className={`pl-2 pr-3 py-0.5 whitespace-pre flex-1 ${hl ? 'text-bone-100' : 'text-bone-300'}`}>
                    {hl && <span className="text-flag-warning mr-2">▸</span>}
                    {line || ' '}
                  </span>
                </div>
              )
            })}
          </pre>
        </div>
      )}
    </div>
  )
}

function Dominators({ analysis }) {
  const all = analysis.dominators
  const [limit, setLimit] = useState(TOP_N)
  const entries = all.slice(0, limit)
  const max = all[0]?.retained_bytes || 1
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat label="reachable heap" value={fmtBytes(analysis.reachable_bytes)} />
        {analysis.unreachable_bytes > 0 && (
          <Stat
            label={`unreachable garbage (${analysis.unreachable_instances?.toLocaleString()} objects)`}
            value={fmtBytes(analysis.unreachable_bytes)}
          />
        )}
      </div>
      <div className="panel overflow-hidden">
        <div className="grid grid-cols-[1fr_auto_auto_auto] gap-x-4 px-5 py-3 border-b border-ink-600/60 label">
          <span>object · exact retained size, not shallow</span>
          <span className="text-right w-24">retained</span>
          <span className="text-right w-16">% heap</span>
          <span className="text-right w-24">shallow</span>
        </div>
        {entries.map((e, i) => {
          const pct = (e.retained_bytes / max) * 100
          return (
            <div key={i} className="grid grid-cols-[1fr_auto_auto_auto] gap-x-4 px-5 py-2.5 items-center text-sm relative border-b border-ink-700/30 last:border-0">
              <div className="absolute inset-y-0 left-0 bg-flag-warning/[0.07]" style={{ width: `${pct}%` }} />
              <span className="min-w-0 relative z-10">
                <span className="font-mono text-xs text-bone-100 truncate block">
                  {e.class_name}
                  <span className="text-bone-500 ml-2">@{e.object_id}</span>
                </span>
                {e.chain?.length > 0 && (
                  <span className="text-[11px] text-bone-500 leading-snug block truncate" title={e.chain.join(' → ')}>
                    ⤷ {e.chain.join(' → ')}
                  </span>
                )}
              </span>
              <span className="font-mono text-xs text-bone-100 text-right tabular-nums w-24 relative z-10">
                {fmtBytes(e.retained_bytes)}
              </span>
              <span className="font-mono text-xs text-bone-300 text-right tabular-nums w-16 relative z-10">
                {e.pct_of_reachable}%
              </span>
              <span className="font-mono text-xs text-bone-500 text-right tabular-nums w-24 relative z-10">
                {fmtBytes(e.shallow_bytes)}
              </span>
            </div>
          )
        })}
        <ShowMore
          shown={entries.length}
          total={all.length}
          onMore={() => setLimit(l => l + TOP_N)}
          onLess={() => setLimit(TOP_N)}
        />
      </div>
    </div>
  )
}

function DuplicateClasses({ entries }) {
  const [limit, setLimit] = useState(TOP_N)
  const visible = entries.slice(0, limit)
  return (
    <div className="panel overflow-hidden">
      <div className="grid grid-cols-[1fr_auto] gap-x-4 px-5 py-3 border-b border-ink-600/60 label">
        <span>class</span>
        <span className="text-right">loaded by</span>
      </div>
      {visible.map((d, i) => (
        <div key={i} className="grid grid-cols-[1fr_auto] gap-x-4 px-5 py-2.5 items-center text-sm border-b border-ink-700/30 last:border-0">
          <span className="font-mono text-xs text-bone-200 truncate">{d.class_name}</span>
          <span className="font-mono text-xs text-bone-400 text-right">
            {d.loader_count} loaders
            <span className="text-bone-500 ml-2 hidden md:inline">({d.loaders.join(', ')})</span>
          </span>
        </div>
      ))}
      <ShowMore
        shown={visible.length}
        total={entries.length}
        onMore={() => setLimit(l => l + TOP_N)}
        onLess={() => setLimit(TOP_N)}
      />
    </div>
  )
}

function Deployments({ deployments, ownership }) {
  const [openId, setOpenId] = useState(null)
  const [limit, setLimit] = useState(TOP_N)
  const visible = deployments.slice(0, limit)
  const threadsFor = (id) => (ownership?.threads || []).filter(t => t.deployment_id === id)

  return (
    <div className="space-y-4">
      {ownership && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Stat label="live threads" value={ownership.live_threads} />
          <Stat label="application threads" value={ownership.application} />
          <Stat label="jvm-internal threads" value={ownership.jvm_internal} />
          <Stat label="deployments" value={deployments.length} />
        </div>
      )}

      <div className="panel overflow-hidden">
        <div className="grid grid-cols-[1fr_auto_auto_auto] gap-x-4 px-5 py-3 border-b border-ink-600/60 label">
          <span>artifact / classloader</span>
          <span className="text-right">classes</span>
          <span className="text-right w-24">retained</span>
          <span className="text-right w-20">threads</span>
        </div>
        {visible.map((d) => {
          const threads = threadsFor(d.id)
          const isOpen = openId === d.id
          const canOpen = threads.length > 0 || d.code_source
          return (
            <div key={d.id} className="border-b border-ink-700/30 last:border-0">
              <div
                className={`grid grid-cols-[1fr_auto_auto_auto] gap-x-4 px-5 py-3 items-center text-sm ${canOpen ? 'cursor-pointer' : ''}`}
                onClick={canOpen ? () => setOpenId(o => (o === d.id ? null : d.id)) : undefined}
              >
                <span className="min-w-0">
                  <span className="font-mono text-xs text-bone-100 truncate block">
                    {canOpen && (
                      <span className={`text-flag-ok mr-1.5 inline-block transition-transform ${isOpen ? 'rotate-90' : ''}`}>▸</span>
                    )}
                    {d.name || d.id}
                    {d.artifact && <span className="text-flag-ok ml-2">{d.artifact}</span>}
                    {d.is_webapp && <span className="badge-neutral ml-2">webapp</span>}
                    {d.stale && <span className="badge-critical ml-2">stale</span>}
                  </span>
                  <span className="text-[11px] text-bone-500 leading-snug block truncate" title={d.loader_class}>
                    {d.loader_class}
                    {d.packages?.length > 0 && ` · ${d.packages.join(', ')}`}
                  </span>
                </span>
                <span className="font-mono text-xs text-bone-300 text-right tabular-nums">
                  {d.class_count.toLocaleString()}
                </span>
                <span className="font-mono text-xs text-bone-100 text-right tabular-nums w-24">
                  {fmtBytes(d.shallow_size_bytes)}
                </span>
                <span className="font-mono text-xs text-right tabular-nums w-20">
                  <span className={d.live_thread_count > 0 ? 'text-bone-100' : 'text-bone-500'}>
                    {d.live_thread_count}
                  </span>
                  {d.thread_count > d.live_thread_count && (
                    <span className="text-bone-500">/{d.thread_count}</span>
                  )}
                </span>
              </div>
              {isOpen && (
                <div className="px-5 pb-3 pl-11 space-y-2 animate-fade-in">
                  {d.code_source && (
                    <div className="font-mono text-[11px] text-bone-400 break-all pt-1">
                      <span className="label mr-2">code source</span>{d.code_source}
                    </div>
                  )}
                  {threads.length > 0 && (
                    <>
                      <div className="label text-bone-400 pt-1">threads created by this deployment</div>
                      <div className="flex flex-wrap gap-1.5">
                        {threads.map((t, j) => (
                          <span
                            key={j}
                            className="font-mono text-[11px] px-2 py-1 rounded bg-ink-800 border border-ink-600/60"
                            title={`${t.class_name}${t.target_class ? ` → ${t.target_class}` : ''} · via ${t.attribution}`}
                          >
                            <span className={t.live ? 'text-bone-200' : 'text-bone-500 line-through'}>
                              {t.name || '<unnamed>'}
                            </span>
                            {t.daemon && <span className="text-bone-500 ml-1.5">daemon</span>}
                          </span>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
          )
        })}
        <ShowMore
          shown={visible.length}
          total={deployments.length}
          onMore={() => setLimit(l => l + TOP_N)}
          onLess={() => setLimit(TOP_N)}
        />
      </div>
    </div>
  )
}

function RecordTypes({ counts }) {
  if (!counts) return null
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1])
  return (
    <div className="panel p-5">
      <div className="flex flex-wrap gap-2">
        {entries.map(([name, n]) => (
          <span
            key={name}
            className="font-mono text-[11px] px-2.5 py-1 rounded bg-ink-800 border border-ink-600/60"
          >
            <span className="text-bone-300">{name}</span>
            <span className="text-bone-500 ml-2">{n.toLocaleString()}</span>
          </span>
        ))}
      </div>
    </div>
  )
}
