package tfa.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A set of episodes judged to be the same kind of flow — grouped by signature
 * (the first K call sites of the episode). A login flow and a nightly batch job
 * must never be compared against each other; episodes that begin identically are
 * the same kind of work.
 *
 * <p>Clusters below a minimum size are marked {@link #isUnderSampled()
 * UNDER_SAMPLED} and excluded from baselining — you cannot derive a consensus
 * from three examples — but they are still reported, since a rare flow is itself
 * interesting.
 */
public final class FlowCluster {

    private final String signature;
    private final List<Episode> episodes = new ArrayList<>();
    private boolean underSampled;

    public FlowCluster(String signature) {
        this.signature = signature;
    }

    public void add(Episode episode) {
        episodes.add(episode);
    }

    public void setUnderSampled(boolean underSampled) {
        this.underSampled = underSampled;
    }

    public String signature()        { return signature; }
    public List<Episode> episodes()  { return Collections.unmodifiableList(episodes); }
    public int size()                { return episodes.size(); }
    public boolean isUnderSampled()  { return underSampled; }

    /** A representative episode for the report; null only if the cluster is empty. */
    public Episode representative() {
        return episodes.isEmpty() ? null : episodes.get(0);
    }

    @Override
    public String toString() {
        return "FlowCluster[" + signature + ", size=" + episodes.size()
                + (underSampled ? ", UNDER_SAMPLED]" : "]");
    }
}
