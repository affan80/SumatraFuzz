import { describe, expect, it } from 'vitest';
import { validTransition } from '../src/index.js';

describe('worker protocol exports', () => {
  it('allows only declared run-state transitions', () => {
    expect(validTransition('created', 'preparing')).toBe(true);
    expect(validTransition('preparing', 'running')).toBe(true);
    expect(validTransition('preparing', 'failed')).toBe(true);
    expect(validTransition('running', 'stopping')).toBe(true);
    expect(validTransition('running', 'failed')).toBe(true);
    expect(validTransition('running', 'interrupted')).toBe(true);
    expect(validTransition('stopping', 'completed')).toBe(true);
    expect(validTransition('stopping', 'failed')).toBe(true);
    expect(validTransition('stopping', 'interrupted')).toBe(true);
    expect(validTransition('completed', 'running')).toBe(false);
    expect(validTransition('failed', 'running')).toBe(false);
    expect(validTransition('interrupted', 'completed')).toBe(false);
    expect(validTransition('running', 'created')).toBe(false);
    expect(validTransition('running', 'preparing')).toBe(false);
    expect(validTransition('created', 'completed')).toBe(false);
  });
});
