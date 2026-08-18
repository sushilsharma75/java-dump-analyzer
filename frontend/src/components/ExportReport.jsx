import { useReport } from '../reportContext'
import { downloadReport } from '../report'

/**
 * Save the whole analysis — verdict, coverage, findings, tables *and* the AI
 * diagnosis — as one self-contained HTML file.
 *
 * The AI section is the reason this reads from ReportContext rather than taking
 * a prop: the diagnosis is produced by a panel further down the page, and the
 * report used to lose it entirely.
 */
export default function ExportReport({ analysis, filename, kind }) {
  const { llm } = useReport()
  const summary = llm?.[kind] || null

  return (
    <div className="panel p-3 flex items-center gap-3 text-sm flex-wrap">
      <span className="label">// report</span>
      <span className="text-bone-400">
        {summary
          ? 'Save this analysis as a single HTML file — the AI diagnosis you generated is included.'
          : 'Save this analysis as a single HTML file. Generate the AI diagnosis below first if you want it included.'}
      </span>
      <button
        onClick={() => downloadReport({ kind, filename, analysis, llm: summary })}
        className="btn-secondary ml-auto"
      >
        ⤓ export report
      </button>
    </div>
  )
}
