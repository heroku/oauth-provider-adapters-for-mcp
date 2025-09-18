const arrayPathExpr = /^\d+(\.|$)/;

function getNestedPaths(paths: string[], prefix: string): string[] {
  return paths
    .filter((path) => path.startsWith(prefix + '.'))
    .map((path) => path.substring(prefix.length + 1));
}

function getGeneralArrayPaths(paths: string[]): string[] {
  return paths.filter((path) => !path.match(arrayPathExpr));
}

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
