package tfa.config;

import tfa.segment.CorrelationIdStrategy;
import tfa.segment.EntryMarkerStrategy;
import tfa.segment.FlowKeyStrategy;
import tfa.segment.IdleGapStrategy;
import tfa.segment.StrategyKind;

import java.util.Set;

/**
 * Segmentation settings (Phase 2). Populated from the Phase 0 report: the
 * strategy choice comes from the entry-point separation verdict, the entry and
 * terminal call-site sets from the ranked candidate lists, and the idle gap from
 * the inter-record gap histogram.
 */
public record SegmentationConfig(
        StrategyKind strategy,
        Set<String> entryCallSites,
        Set<String> terminalCallSites,
        long idleGapMillis
) {
    public SegmentationConfig {
        entryCallSites = entryCallSites == null ? Set.of() : Set.copyOf(entryCallSites);
        terminalCallSites = terminalCallSites == null ? Set.of() : Set.copyOf(terminalCallSites);
    }

    /** Build the configured strategy instance. */
    public FlowKeyStrategy buildStrategy() {
        return switch (strategy) {
            case ENTRY_MARKER -> {
                if (entryCallSites.isEmpty()) {
                    throw new IllegalArgumentException(
                            "ENTRY_MARKER strategy requires a non-empty entryCallSites set");
                }
                yield new EntryMarkerStrategy(entryCallSites, terminalCallSites);
            }
            case IDLE_GAP -> {
                if (idleGapMillis <= 0) {
                    throw new IllegalArgumentException(
                            "IDLE_GAP strategy requires idleGapMillis > 0");
                }
                yield new IdleGapStrategy(idleGapMillis, terminalCallSites);
            }
            case CORRELATION_ID -> new CorrelationIdStrategy();
        };
    }
}
