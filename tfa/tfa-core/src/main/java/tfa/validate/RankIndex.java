package tfa.validate;

import tfa.model.Finding;
import tfa.rank.FindingRanker;
import tfa.rank.RankedFinding;

import java.util.HashMap;
import java.util.Map;

/**
 * Maps a finding's dedupe key to its 1-based report rank (position among the
 * non-suppressed findings, in ranked order). Suppressed findings are recorded
 * separately so callers can distinguish "suppressed" from "not detected".
 */
public final class RankIndex {

    private final Map<String, Integer> rankByKey = new HashMap<>();
    private final Map<String, String> suppressedReasonByKey = new HashMap<>();

    public RankIndex(FindingRanker.RankingResult ranking) {
        int rank = 0;
        for (RankedFinding rf : ranking.ranked()) {
            String key = rf.representative().dedupeKey(rf.clusterSignature());
            if (rf.suppressed()) {
                suppressedReasonByKey.put(key, rf.suppressionReason());
            } else {
                rank++;
                rankByKey.put(key, rank);
            }
        }
    }

    /** 1-based report rank of a raw finding in the given cluster, or null if not ranked (e.g. suppressed/absent). */
    public Integer rankOf(Finding finding, String clusterSignature) {
        return rankByKey.get(finding.dedupeKey(clusterSignature));
    }

    public boolean isSuppressed(Finding finding, String clusterSignature) {
        return suppressedReasonByKey.containsKey(finding.dedupeKey(clusterSignature));
    }

    public String suppressionReason(Finding finding, String clusterSignature) {
        return suppressedReasonByKey.get(finding.dedupeKey(clusterSignature));
    }
}
