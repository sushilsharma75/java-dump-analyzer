import { createContext, useCallback, useContext, useMemo, useState } from 'react'

/**
 * Holds the AI diagnosis for each kind of analysis so it can outlive the panel
 * that produced it.
 *
 * The diagnosis used to live in LLMPanel's local state, which meant the exported
 * report — assembled elsewhere — had no way to see it. Keeping it here is what
 * lets "export report" include the AI section instead of silently dropping it.
 *
 * Keys are the LLMPanel `kind`: 'heap' | 'thread' | 'gc' | 'unified'.
 */
const ReportContext = createContext(null)

export function ReportProvider({ children }) {
  const [llm, setLlmState] = useState({})

  const setLLM = useCallback((kind, summary) => {
    setLlmState((prev) => {
      if (!summary) {
        if (!(kind in prev)) return prev
        const next = { ...prev }
        delete next[kind]
        return next
      }
      return { ...prev, [kind]: summary }
    })
  }, [])

  const value = useMemo(() => ({ llm, setLLM }), [llm, setLLM])
  return <ReportContext.Provider value={value}>{children}</ReportContext.Provider>
}

/** Safe outside a provider (returns an inert store) so panels stay standalone. */
export function useReport() {
  return useContext(ReportContext) || { llm: {}, setLLM: () => {} }
}
