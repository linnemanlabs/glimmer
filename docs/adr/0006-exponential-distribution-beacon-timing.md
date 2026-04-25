**Date:** 2026-04-08

**Status:** Accepted

**Context:** Fixed intervals with uniform jitter produce a rectangular histogram centered on the base interval. This is trivially identifiable as periodic beaconing with jitter by statistical analysis. Even with high jitter percentages, the uniform distribution has sharp cutoffs at min and max that reveal the configuration parameters.
 
**Decision:** Use exponential distribution (inverse transform sampling: `-base * ln(uniform_random)`) for beacon intervals. Apply a soft minimum at 30-50% of base with its own jitter to prevent suspicious clustering. Maximum capped at 10x base.
 
**Consequences:**
- Histogram shows a decay curve consistent with event-driven application traffic, not timer-driven polling
- Most intervals cluster shorter than the mean, with occasional long-tail gaps (3-5x base)
- Long gaps break periodicity detection and look like natural inactivity
- No hard floor at a round number, the soft minimum has its own jitter so no clustering at the cutoff
- Requires `libm.so.6` dependency for the `ln()` function (could be eliminated with a hand-rolled approximation)
- At scale (hundreds of samples), statistical analysis could still identify the exponential shape but requires far more data than identifying uniform jitter