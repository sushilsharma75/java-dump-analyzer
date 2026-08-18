/**
 * Renders a source code snippet with line numbers and a highlighted line.
 * Used inline in finding cards and stack frames when a source session is attached.
 */
export default function SourceSnippet({ location, compact = false }) {
  if (!location) return null

  const { repo_path, snippet, class_name, method, line, is_user_code } = location

  return (
    <div className={`panel-inset overflow-hidden ${compact ? '' : 'mt-2'}`}>
      <div className="px-3 py-2 border-b border-ink-600/40 flex items-center gap-2 flex-wrap bg-ink-950/40">
        <span className={`badge ${is_user_code ? 'badge-warning' : 'badge-neutral'}`}>
          {is_user_code ? 'user code' : 'library'}
        </span>
        {repo_path ? (
          <span className="font-mono text-[11px] text-bone-200 truncate">
            {repo_path}
            {line && <span className="text-bone-500">:{line}</span>}
          </span>
        ) : (
          <span className="font-mono text-[11px] text-bone-400 truncate">
            {class_name}.{method}
            {line && <span className="text-bone-500">:{line}</span>}
            <span className="ml-2 text-bone-500">(not in attached source)</span>
          </span>
        )}
      </div>

      {snippet && snippet.lines.length > 0 ? (
        <div className="font-mono text-[11px] leading-relaxed overflow-x-auto">
          <pre className="p-0 m-0">
            {snippet.lines.map((rawLine, i) => {
              const ln = snippet.start_line + i
              const isHighlight = ln === snippet.highlight_line
              return (
                <div
                  key={i}
                  className={`flex ${isHighlight ? 'bg-flag-warning/10' : ''}`}
                >
                  <span className={`select-none px-3 py-0.5 text-right shrink-0 w-12 tabular-nums ${
                    isHighlight ? 'text-flag-warning' : 'text-bone-500'
                  }`}>
                    {ln}
                  </span>
                  <span className={`pl-2 pr-3 py-0.5 whitespace-pre flex-1 ${
                    isHighlight ? 'text-bone-100' : 'text-bone-300'
                  }`}>
                    {isHighlight && (
                      <span className="text-flag-warning mr-2">▸</span>
                    )}
                    {rawLine || ' '}
                  </span>
                </div>
              )
            })}
          </pre>
        </div>
      ) : (
        <div className="px-3 py-2 font-mono text-[11px] text-bone-500">
          {snippet ? 'line out of range' : 'snippet unavailable'}
        </div>
      )}
    </div>
  )
}
