/**
 * ResilienceManager unit tests
 * Tests resilience patterns including retry logic and circuit breaker functionality
 */

import { expect } from 'chai';
import { ResilienceManager } from './resilience-manager.js';

describe('ResilienceManager', () => {
  // Reset circuit state before each test
  beforeEach(() => {
    ResilienceManager.resetAllCircuits();
  });

  describe('Successful operations', () => {
    it('should return result on first success', async () => {
      const operation = async () => 'success';
      const errorNormalizer = (error: unknown) => new Error(String(error));

      const result = await ResilienceManager.executeWithResilience(
        operation,
        { endpoint: '/test' },
        errorNormalizer
      );

      expect(result).to.equal('success');
    });

    it('should reset circuit breaker on success', async () => {
      const operation = async () => 'success';
      const errorNormalizer = (error: unknown) => new Error(String(error));

      // Prime the circuit with failures
      ResilienceManager['circuitBreakers'].set('/test', {
        consecutiveFailures: 2,
      });

      const result = await ResilienceManager.executeWithResilience(
        operation,
        { endpoint: '/test' },
        errorNormalizer
      );

      expect(result).to.equal('success');
      const circuitState = ResilienceManager.getCircuitState('/test');
      expect(circuitState?.consecutiveFailures).to.equal(0);
    });
  });

  describe('Retry behavior', () => {
    it('should retry on failure and succeed', async () => {
      let attempts = 0;
      const operation = async () => {
        attempts++;
        if (attempts < 2) {
          throw new Error('temporary failure');
        }
        return 'success';
      };
      const errorNormalizer = (error: unknown) => new Error(String(error));

      const result = await ResilienceManager.executeWithResilience(
        operation,
        { endpoint: '/test', maxRetries: 2 },
        errorNormalizer
      );

      expect(result).to.equal('success');
      expect(attempts).to.equal(2);
    });

    it('should respect maxRetries limit', async () => {
      let attempts = 0;
      const operation = async () => {
        attempts++;
        throw new Error('persistent failure');
      };
      const errorNormalizer = (error: unknown) =>
        new Error(`Normalized: ${error}`);

      try {
        await ResilienceManager.executeWithResilience(
          operation,
          { endpoint: '/test', maxRetries: 1 },
          errorNormalizer
        );
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include(
          'Normalized: Error: persistent failure'
        );
        expect(attempts).to.equal(2); // 1 initial + 1 retry
      }
    });

    it('should use exponential backoff', async () => {
      const startTime = Date.now();
      let attempts = 0;
      const operation = async () => {
        attempts++;
        throw new Error('failure');
      };
      const errorNormalizer = (error: unknown) => new Error(String(error));

      try {
        await ResilienceManager.executeWithResilience(
          operation,
          { endpoint: '/test', maxRetries: 2, backoffMs: 10 },
          errorNormalizer
        );
      } catch {
        // Expected to fail
      }

      const elapsed = Date.now() - startTime;
      expect(attempts).to.equal(3); // 1 initial + 2 retries
      expect(elapsed).to.be.greaterThan(10); // Should have some backoff delay
    });
  });

  describe('Circuit breaker functionality', () => {
    it('should track consecutive failures', async () => {
      const operation = async () => {
        throw new Error('failure');
      };
      const errorNormalizer = (error: unknown) => new Error(String(error));

      try {
        await ResilienceManager.executeWithResilience(
          operation,
          { endpoint: '/test', maxRetries: 0 },
          errorNormalizer
        );
      } catch {
        // Expected
      }

      const circuitState = ResilienceManager.getCircuitState('/test');
      expect(circuitState?.consecutiveFailures).to.equal(1);
    });

    it('should open circuit after failure threshold', async () => {
      const operation = async () => {
        throw new Error('failure');
      };
      const errorNormalizer = (error: unknown) => new Error(String(error));

      // Trigger failures to open circuit
      for (let i = 0; i < 3; i++) {
        try {
          await ResilienceManager.executeWithResilience(
            operation,
            { endpoint: '/test', maxRetries: 0, failureThreshold: 3 },
            errorNormalizer
          );
        } catch {
          // Expected
        }
      }

      const circuitState = ResilienceManager.getCircuitState('/test');
      expect(circuitState?.consecutiveFailures).to.equal(3);
      expect(circuitState?.openedUntil).to.be.a('number');
      expect(circuitState?.openedUntil).to.be.greaterThan(Date.now());
    });

    it('should reject requests when circuit is open', async () => {
      const operation = async () => 'should not be called';
      const errorNormalizer = (error: unknown) => new Error(String(error));

      // Manually open the circuit
      ResilienceManager['circuitBreakers'].set('/test', {
        consecutiveFailures: 3,
        openedUntil: Date.now() + 60000,
      });

      try {
        await ResilienceManager.executeWithResilience(
          operation,
          { endpoint: '/test' },
          errorNormalizer
        );
        expect.fail('Should have thrown');
      } catch (error: any) {
        expect(error.message).to.include('Circuit breaker is open');
      }
    });

    it('should allow requests after circuit timeout', async () => {
      const operation = async () => 'success';
      const errorNormalizer = (error: unknown) => new Error(String(error));

      // Manually set circuit to recently expired
      ResilienceManager['circuitBreakers'].set('/test', {
        consecutiveFailures: 3,
        openedUntil: Date.now() - 1000, // Expired 1 second ago
      });

      const result = await ResilienceManager.executeWithResilience(
        operation,
        { endpoint: '/test' },
        errorNormalizer
      );

      expect(result).to.equal('success');
    });
  });

  describe('Configuration options', () => {
    it('should use custom circuit key', async () => {
      const operation = async () => {
        throw new Error('failure');
      };
      const errorNormalizer = (error: unknown) => new Error(String(error));

      try {
        await ResilienceManager.executeWithResilience(
          operation,
          { endpoint: '/test', circuitKey: 'custom-key', maxRetries: 0 },
          errorNormalizer
        );
      } catch {
        // Expected
      }

      const customState = ResilienceManager.getCircuitState('custom-key');
      const defaultState = ResilienceManager.getCircuitState('/test');

      expect(customState?.consecutiveFailures).to.equal(1);
      expect(defaultState).to.be.undefined;
    });

    it('should use default values for missing options', async () => {
      let attempts = 0;
      const operation = async () => {
        attempts++;
        throw new Error('failure');
      };
      const errorNormalizer = (error: unknown) => new Error(String(error));

      try {
        await ResilienceManager.executeWithResilience(
          operation,
          { endpoint: '/test' }, // Use all defaults
          errorNormalizer
        );
      } catch {
        // Expected
      }

      expect(attempts).to.equal(3); // 1 + DEFAULT_MAX_RETRIES (2)
    });
  });

  describe('Utility methods', () => {
    it('should return circuit state', () => {
      ResilienceManager['circuitBreakers'].set('/test', {
        consecutiveFailures: 2,
        openedUntil: 12345,
      });

      const state = ResilienceManager.getCircuitState('/test');
      expect(state?.consecutiveFailures).to.equal(2);
      expect(state?.openedUntil).to.equal(12345);
    });

    it('should reset specific circuit', () => {
      ResilienceManager['circuitBreakers'].set('/test1', {
        consecutiveFailures: 1,
      });
      ResilienceManager['circuitBreakers'].set('/test2', {
        consecutiveFailures: 2,
      });

      ResilienceManager.resetCircuit('/test1');

      expect(ResilienceManager.getCircuitState('/test1')).to.be.undefined;
      expect(
        ResilienceManager.getCircuitState('/test2')?.consecutiveFailures
      ).to.equal(2);
    });

    it('should get circuit statistics', () => {
      ResilienceManager['circuitBreakers'].set('/test1', {
        consecutiveFailures: 1,
      });
      ResilienceManager['circuitBreakers'].set('/test2', {
        consecutiveFailures: 2,
      });

      const stats = ResilienceManager.getCircuitStats();
      expect(stats.size).to.equal(2);
      expect(stats.get('/test1')?.consecutiveFailures).to.equal(1);
      expect(stats.get('/test2')?.consecutiveFailures).to.equal(2);
    });
  });
});
