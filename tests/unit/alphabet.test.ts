/* -----------------------------------------------------------------------------
 * The Cyberiada State Machine JavaScript Library
 *
 * The EXT-FA alphabet grammar tests
 *
 * Copyright (C) 2026 Alexey Fedoseev <aleksey@fedoseev.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/
 *
 * ----------------------------------------------------------------------------- */

import {
  AlphabetError,
  FA_INPUT,
  FA_INPUT_RE,
  FA_OUTPUT_RE,
  parse,
  translate,
} from '../../src/core/alphabet';

function matches(expr: string, symbol: string): boolean {
  return new RegExp(`^(?:${translate(expr)})$`, 'u').test(symbol);
}

test('ranges and counts', () => {
  expect(matches('[a-z]{1,10}', 'abc')).toBe(true);
  expect(matches('[a-z]{1,10}', 'ABC')).toBe(false);
  expect(matches('[a-z]{1,10}', 'abcdefghijk')).toBe(false);
  expect(matches('[0-9]{2}', '42')).toBe(true);
  expect(matches('[0-9]{2}', '4')).toBe(false);
});

test('group alternatives and optional', () => {
  expect(matches('(START|STOP)', 'STOP')).toBe(true);
  expect(matches('(START|STOP)', 'START|STOP')).toBe(false);
  expect(matches('ab?', 'a')).toBe(true);
  expect(matches('ab?', 'ab')).toBe(true);
  expect(matches('(ab){2}c?', 'abab')).toBe(true);
});

test('escapes and any character', () => {
  expect(matches('(__|\\-\\-)', '--')).toBe(true);
  expect(matches('a\\.b', 'a.b')).toBe(true);
  expect(matches('a\\.b', 'axb')).toBe(false);
  expect(matches('\\\\', '\\')).toBe(true);
  expect(matches('.', 'x')).toBe(true);
  expect(matches('.', 'ж')).toBe(true);
  expect(matches('.', ' ')).toBe(false);
  expect(matches('[\\]\\-]', '-')).toBe(true);
});

test.each([
  'a*',
  'a+',
  '^a',
  'a$', // infinite or anchored constructs
  '{2}',
  '?',
  'a{3,1}',
  'a{1, 2}',
  'a{x}',
  '(a',
  'a)',
  'a|b',
  '[a',
  'a]',
  'a}',
  'a-b',
  'a,b',
  'a\\',
  'a\\x',
  '[]',
  '()',
  '(a|)',
  '[b-a]',
  '[^a]',
  '',
])('rejected expression %j', (expr) => {
  expect(() => translate(expr)).toThrow(AlphabetError);
});

test('plain alphabet lines', () => {
  const table = parse(FA_INPUT, 'Start\nStop\nPause\n');
  expect(table.errors).toEqual([]);
  expect(table.symbols).toEqual(['Start', 'Stop', 'Pause']);
  expect(table.contains('Stop')).toBe(true);
  expect(table.contains('stop')).toBe(false);
});

test('empty and blank lines reported', () => {
  const table = parse(FA_INPUT, 'a\n\nb');
  expect(table.errors.map(([line]) => line)).toEqual([1]);
  expect(parse(FA_INPUT, '  \n').errors).toEqual([[0, 'the alphabet is empty']]);
});

test('regex alphabet membership excludes reserved', () => {
  const table = parse(FA_INPUT_RE, '[a-z]{1,10}\n[0-9]{1,2}\n(__|\\-\\-)');
  expect(table.errors).toEqual([]);
  expect(table.contains('exits')).toBe(true);
  expect(table.contains('--')).toBe(true);
  expect(table.contains('exit')).toBe(false);
  expect(table.contains('Exit')).toBe(false);
});

test('regex alphabet error names the line', () => {
  const table = parse(FA_OUTPUT_RE, '[01]\nx*');
  expect(table.errors).toHaveLength(1);
  const [line, message] = table.errors[0];
  expect(line).toBe(1);
  expect(message).toContain("'*'");
});
