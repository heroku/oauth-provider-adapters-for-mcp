/**
 * Resilience Manager - Handles retry logic with circuit breaker patterns
 * Extracted from BaseOAuthAdapter for reusability across different contexts
 */

/**
 * Circuit breaker state for tracking endpoint failures
 */
export type CircuitBreakerState = {
  consecutiveFailures: number;
  openedUntil?: number;
};

/**
 * Resilience execution context options
 */
export interface ResilienceContext {
  /** Endpoint identifier for circuit breaker tracking */
  endpoint: string;
  /** Maximum retry attempts (default: 2) */
  maxRetries?: number;
  /** Base backoff delay in milliseconds (default: 300) */
  backoffMs?: number;
  /** Circuit breaker key for grouping failures (default: endpoint) */
  circuitKey?: string;
  /** Failures required to open circuit (default: 3) */
  failureThreshold?: number;
  /** Time circuit stays open in milliseconds (default: 60000) */
  circuitOpenMs?: number;
}

/**
 * Error normalizer function type - returns any error type
 */
export type ErrorNormalizer<T = unknown> = (
  error: unknown,
  context: { endpoint: string }
) => T;

/**
 * ResilienceManager - Provides retry logic with circuit breaker patterns
 *
 * Features:
 * - Exponential backoff retries
 * - Circuit breaker pattern to prevent cascading failures
 * - Configurable failure thresholds and timeouts
 * - Shared circuit state across instances
 */
export class ResilienceManager {
  /** Default configuration values */
  public static readonly DEFAULT_MAX_RETRIES = 2;
  public static readonly DEFAULT_BACKOFF_MS = 300;
  public static readonly DEFAULT_CIRCUIT_FAILURE_THRESHOLD = 3;
  public static readonly DEFAULT_CIRCUIT_OPEN_MS = 60_000; // 60s

  /** Global circuit breaker state storage */
  private static circuitBreakers: Map<string, CircuitBreakerState> = new Map();

  /**
   * Execute an operation with retry logic and circuit breaker protection
   *
   * @param operation - Async operation to execute
   * @param context - Resilience configuration options
   * @param errorNormalizer - Function to normalize errors before re-throwing
   * @returns Promise resolving to operation result
   * @throws Normalized error if all retries fail or circuit is open
   */
  public static async executeWithResilience<T, E = Error>(
    operation: () => Promise<T>,
    context: ResilienceContext,
    errorNormalizer: ErrorNormalizer<E>
  ): Promise<T> {
    const {
      endpoint,
      maxRetries = ResilienceManager.DEFAULT_MAX_RETRIES,
      backoffMs = ResilienceManager.DEFAULT_BACKOFF_MS,
      circuitKey = endpoint,
      failureThreshold = ResilienceManager.DEFAULT_CIRCUIT_FAILURE_THRESHOLD,
      circuitOpenMs = ResilienceManager.DEFAULT_CIRCUIT_OPEN_MS,
    } = context;

    // Circuit breaker: check if circuit is open
    const circuit = ResilienceManager.circuitBreakers.get(circuitKey) || {
      consecutiveFailures: 0,
    };

    if (circuit.openedUntil && Date.now() < circuit.openedUntil) {
      const circuitError = new Error(
        'Circuit breaker is open due to recent failures. Try again later.'
      );
      throw errorNormalizer(circuitError, { endpoint });
    }

    let lastError: unknown;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const result = await operation();

        // Reset circuit breaker on success
        ResilienceManager.circuitBreakers.set(circuitKey, {
          consecutiveFailures: 0,
        });

        return result;
      } catch (error) {
        lastError = error;

        // Exponential backoff before retry, except after last attempt
        if (attempt < maxRetries) {
          const wait = backoffMs * Math.pow(2, attempt);
          await new Promise((resolve) => setTimeout(resolve, wait));
          continue;
        }
      }
    }

    // Update circuit breaker on failure exhaustion
    const failures = (circuit.consecutiveFailures || 0) + 1;
    const shouldOpen = failures >= failureThreshold;
    const newState: CircuitBreakerState = {
      consecutiveFailures: failures,
    };

    if (shouldOpen) {
      newState.openedUntil = Date.now() + circuitOpenMs;
    }

    ResilienceManager.circuitBreakers.set(circuitKey, newState);

    // Normalize and re-throw the error
    throw errorNormalizer(lastError, { endpoint });
  }

  /**
   * Get current circuit breaker state for debugging/monitoring
   * @param circuitKey - Circuit breaker key
   * @returns Current circuit state or undefined if not found
   */
  public static getCircuitState(
    circuitKey: string
  ): CircuitBreakerState | undefined {
    return ResilienceManager.circuitBreakers.get(circuitKey);
  }

  /**
   * Reset circuit breaker state (useful for testing or manual recovery)
   * @param circuitKey - Circuit breaker key to reset
   */
  public static resetCircuit(circuitKey: string): void {
    ResilienceManager.circuitBreakers.delete(circuitKey);
  }

  /**
   * Reset all circuit breakers (useful for testing)
   */
  public static resetAllCircuits(): void {
    ResilienceManager.circuitBreakers.clear();
  }

  /**
   * Get statistics about all active circuits
   * @returns Map of circuit keys to their current states
   */
  public static getCircuitStats(): Map<string, CircuitBreakerState> {
    return new Map(ResilienceManager.circuitBreakers);
  }
}
