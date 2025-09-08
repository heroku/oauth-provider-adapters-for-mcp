/**
 * Basic test file to verify dual build output (CJS/ESM)
 */

export const version = '0.0.1';

export function greet(name: string): string {
  return `Hello, ${name}!`;
}

export default {
  version,
  greet,
};
