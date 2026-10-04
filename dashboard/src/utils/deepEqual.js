/**
 * Deep equality comparison for objects and arrays.
 * Used to prevent unnecessary state updates when data hasn't changed.
 */

export const deepEqual = (a, b) => {
  // Handle primitive types
  if (a === b) return true;
  
  if (a == null || b == null) return a === b;
  if (typeof a !== 'object' || typeof b !== 'object') return a === b;

  // Handle arrays
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    return a.every((item, idx) => deepEqual(item, b[idx]));
  }

  // Handle objects
  if (Array.isArray(a) || Array.isArray(b)) return false;

  const keysA = Object.keys(a);
  const keysB = Object.keys(b);

  if (keysA.length !== keysB.length) return false;

  return keysA.every((key) => deepEqual(a[key], b[key]));
};

/**
 * Shallow equality comparison for object properties.
 * Faster than deepEqual for flat objects.
 */
export const shallowEqual = (a, b) => {
  if (a === b) return true;
  if (a == null || b == null) return false;

  const keysA = Object.keys(a);
  const keysB = Object.keys(b);

  if (keysA.length !== keysB.length) return false;

  return keysA.every((key) => a[key] === b[key]);
};
