const arrayPathExpr = /^\d+(\.|$)/;

function getNestedPaths(paths: string[], prefix: string): string[] {
  return paths
    .filter((path) => path.startsWith(prefix + '.'))
    .map((path) => path.substring(prefix.length + 1));
}

function getGeneralArrayPaths(paths: string[]): string[] {
  return paths.filter((path) => !path.match(arrayPathExpr));
}

/**
 * Redacts sensitive values in an object or array by replacing them with a redaction string.
 *
 * This function recursively traverses the provided object/array and replaces values at
 * specified paths with a redaction placeholder. It supports nested object properties,
 * array indices, and mixed structures with dot notation paths.
 *
 * @template T - The type of the input object/array to preserve type safety
 * @param obj - The object or array to redact values from. Can be any type including
 *              primitives, null, or undefined (which are returned as-is)
 * @param paths - Array of dot-notation paths specifying which values to redact.
 *                Examples:
 *                - `['password']` - redacts top-level 'password' property
 *                - `['user.email']` - redacts nested 'email' property in 'user' object
 *                - `['items.0.secret']` - redacts 'secret' property in first array item
 *                - `['users.password']` - redacts 'password' in all objects within 'users' array
 * @param redaction - The string to replace redacted values with. Defaults to '[redacted]'
 *
 * @returns A new object/array of the same type with specified values redacted.
 *          Non-object types (primitives, null, undefined) are returned unchanged.
 *
 * @example
 * ```typescript
 * // Simple object redaction
 * const user = { name: 'bob', email: 'bob@example.com', password: 'secret123' };
 * const safe = redact(user, ['email', 'password']);
 * // Result: { name: 'bob', email: '[redacted]', password: '[redacted]' }
 *
 * // Nested object redaction
 * const data = { user: { name: 'bob', credentials: { token: 'abc123' } } };
 * const safe = redact(data, ['user.credentials.token']);
 * // Result: { user: { name: 'bob', credentials: { token: '[redacted]' } } }
 *
 * // Array redaction
 * const users = [{ name: 'bob', pass: 'secret' }, { name: 'alice', pass: 'hidden' }];
 * const safe = redact(users, ['pass']);
 * // Result: [{ name: 'bob', pass: '[redacted]' }, { name: 'alice', pass: '[redacted]' }]
 *
 * // Custom redaction string
 * const obj = { secret: 'value' };
 * const safe = redact(obj, ['secret'], '***HIDDEN***');
 * // Result: { secret: '***HIDDEN***' }
 * ```
 */
export function redact<T>(
  obj: T,
  paths: string[],
  redaction = '[redacted]'
): T {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }

  if (paths.length === 0) {
    return obj;
  }

  const pathSet = new Set(paths);

  if (Array.isArray(obj)) {
    return obj.map((item, index) => {
      const indexStr = index.toString();

      if (pathSet.has(indexStr)) {
        return redaction;
      }

      const nestedPaths = getNestedPaths(paths, indexStr);
      const generalPaths = getGeneralArrayPaths(paths);
      const allNestedPaths = [...nestedPaths, ...generalPaths];

      return redact(item, allNestedPaths, redaction);
    }) as T;
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (pathSet.has(key)) {
      result[key] = redaction;
    } else {
      const nestedPaths = getNestedPaths(paths, key);
      result[key] = redact(value, nestedPaths, redaction);
    }
  }

  return result as T;
}
