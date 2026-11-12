/**
 * Every k6 script declares its thresholds through thresholds(functional, latency).
 *
 * Functional thresholds (status classes, error rates, check rates, counts) always gate. Latency
 * thresholds gate only when the backend runs on its own CPU architecture. The release images are
 * linux/amd64; on an arm64 Docker host they run under emulation, and there the same backend jars at
 * 50 concurrent tasks used about 1.3 of their 4 CPUs and were 6x slower cold and 50x slower warm
 * than native (measurements in tests/load/README.md). A latency budget on an emulated backend
 * measures the emulator, so the release smoke sets K6_LATENCY_BUDGETS=record
 * there: the latency trends are still measured and printed in the summary, and the smoke records
 * that they were not qualified. Unset, the mode is gate.
 *
 * Latency belongs in these thresholds, never inside a check(): a check mixes it back into the
 * functional rate.
 */
export function thresholds(functional, latency) {
  const mode = (typeof __ENV !== 'undefined' && __ENV.K6_LATENCY_BUDGETS) || 'gate';
  if (mode === 'gate') return Object.assign({}, functional, latency);
  if (mode === 'record') return Object.assign({}, functional);
  throw new Error(`K6_LATENCY_BUDGETS must be gate or record, not ${mode}`);
}
