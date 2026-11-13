import { describe, test } from 'vitest';
import { hasRealCaptures } from './fixtures';

/** `test` / `describe` that run only when the real captures are present (see fixtures.ts). */
export const realTest = test.skipIf(!hasRealCaptures);
export const realDescribe = describe.skipIf(!hasRealCaptures);
