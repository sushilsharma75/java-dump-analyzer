package tfa.detect;

import java.util.List;
import java.util.Optional;

/**
 * Sequence comparison for divergence detection. Provides Levenshtein edit
 * distance (used to tell "same as modal" from "different") and the FIRST position
 * where an episode departs from the modal sequence — not the whole diff.
 *
 * <p>The first departure is located by common-prefix alignment: for a wrong-branch
 * substitution (the dominant real case, and the success-test defect) this is
 * exactly the first edit-distance operation. Trailing shortfalls (the episode is a
 * prefix of the modal sequence) are left to the truncation detector, not reported
 * as divergences.
 */
public final class SequenceDiff {

    private SequenceDiff() {}

    public enum Kind {
        /** The episode took a different call site than the majority at this position. */
        SUBSTITUTION,
        /** The episode continued past where the modal sequence ended. */
        INSERTION
    }

    public record Divergence(int index, String observedCallSite, Kind kind) {}

    /** Levenshtein edit distance between two call-site sequences. */
    public static int editDistance(List<String> a, List<String> b) {
        int m = a.size();
        int n = b.size();
        int[] prev = new int[n + 1];
        int[] cur = new int[n + 1];
        for (int j = 0; j <= n; j++) {
            prev[j] = j;
        }
        for (int i = 1; i <= m; i++) {
            cur[0] = i;
            for (int j = 1; j <= n; j++) {
                int cost = a.get(i - 1).equals(b.get(j - 1)) ? 0 : 1;
                cur[j] = Math.min(Math.min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            int[] tmp = prev;
            prev = cur;
            cur = tmp;
        }
        return prev[n];
    }

    /**
     * The first position where {@code observed} departs from {@code modal}, or
     * empty if {@code observed} matches the modal sequence or is a prefix of it
     * (a shortfall the truncation detector owns).
     */
    public static Optional<Divergence> firstDivergence(List<String> modal, List<String> observed) {
        int p = commonPrefix(modal, observed);
        boolean modalExhausted = p == modal.size();
        boolean observedExhausted = p == observed.size();

        if (modalExhausted && observedExhausted) {
            return Optional.empty();                 // identical
        }
        if (observedExhausted) {
            return Optional.empty();                 // observed is a prefix -> truncation
        }
        if (modalExhausted) {
            // observed continued past the modal sequence
            return Optional.of(new Divergence(p, observed.get(p), Kind.INSERTION));
        }
        // mismatch within the common region: a wrong branch
        return Optional.of(new Divergence(p, observed.get(p), Kind.SUBSTITUTION));
    }

    private static int commonPrefix(List<String> a, List<String> b) {
        int n = Math.min(a.size(), b.size());
        int i = 0;
        while (i < n && a.get(i).equals(b.get(i))) {
            i++;
        }
        return i;
    }
}
