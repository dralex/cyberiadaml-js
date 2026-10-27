/* -----------------------------------------------------------------------------
 * The Cyberiada State Machine JavaScript Library
 *
 * The EXT-FA alphabet comments: symbol lists and restricted regular expressions
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

import { RESERVED } from './actions';
import { compareText, repr } from './util';

export const FA_INPUT = 'FA_INPUT';
export const FA_INPUT_RE = 'FA_INPUT_RE';
export const FA_OUTPUT = 'FA_OUTPUT';
export const FA_OUTPUT_RE = 'FA_OUTPUT_RE';
export const INPUT_NAMES = [FA_INPUT, FA_INPUT_RE];
export const OUTPUT_NAMES = [FA_OUTPUT, FA_OUTPUT_RE];
export const NAMES = [...INPUT_NAMES, ...OUTPUT_NAMES];
export const RE_SUFFIX = '_RE';

export const EOF = 'EOF';
export const RESERVED_SYMBOLS = [...RESERVED, 'ANY', 'UNKNOWN', EOF]; // FA 3.4

const ESCAPABLE = '.[]-{},?()|\\'; // the characters an alphabet escapes (FA 4)
const FORBIDDEN = '*+^$'; // the constructs of an infinite set
const ANY_CHAR = '[^\\s]'; // '.' - one printable non-space character
const COUNT_RE = /\{(\d+)(?:,(\d+))?\}/y;
const SPECIAL = '[]{}()*+?.\\^$|/'; // escaped outside a class (the u flag)
const CLASS_SPECIAL = ']\\^-'; // escaped inside a class

/** A restricted regular expression outside the FA 4 grammar. */
export class AlphabetError extends Error {
  constructor(
    message: string,
    public position: number,
  ) {
    super(message);
    this.name = 'AlphabetError';
  }
}

/** The symbols (or the patterns) of one FA_* comment. */
export class Alphabet {
  regex: boolean;
  symbols: string[] = [];
  patterns: RegExp[] = [];
  errors: Array<[number, string]> = []; // [line index, message]

  constructor(public name: string) {
    this.regex = name.endsWith(RE_SUFFIX);
  }

  /** Whether the symbol is a member of the alphabet. */
  contains(symbol: string): boolean {
    if (RESERVED_SYMBOLS.includes(symbol)) {
      return false;
    }
    if (this.regex) {
      return this.patterns.some((p) => p.test(symbol));
    }
    return this.symbols.includes(symbol);
  }
}

/** Parse an alphabet comment body: one symbol or pattern per line. */
export function parse(name: string, body: string | null): Alphabet {
  const alphabet = new Alphabet(name);
  const lines = (body ?? '').split('\n');
  const filled = lines.map((line, i) => (line.trim() ? i : -1)).filter((i) => i >= 0);
  if (!filled.length) {
    alphabet.errors.push([0, 'the alphabet is empty']);
    return alphabet;
  }
  for (let i = filled[0]; i <= filled[filled.length - 1]; i++) {
    const line = lines[i].trim();
    if (!line) {
      alphabet.errors.push([i, 'empty line in the alphabet']);
    } else if (alphabet.regex) {
      try {
        alphabet.patterns.push(new RegExp(`^(?:${translate(line)})$`, 'u'));
      } catch (err) {
        if (!(err instanceof AlphabetError)) {
          throw err;
        }
        alphabet.errors.push([i, `${err.message} (column ${err.position + 1})`]);
      }
    } else {
      alphabet.symbols.push(line);
    }
  }
  return alphabet;
}

/** The pattern source of a restricted regular expression (FA 4). */
export function translate(expr: string): string {
  if (!expr) {
    throw new AlphabetError('empty expression', 0);
  }
  const [source] = sequence(expr, 0, true);
  return source;
}

function escapeChar(ch: string, special: string): string {
  return special.includes(ch) ? '\\' + ch : ch;
}

function sequence(expr: string, start: number, top: boolean): [string, number] {
  const parts: string[] = [];
  let quantifiable = false;
  let pos = start;
  while (pos < expr.length) {
    const ch = expr[pos];
    if (ch === ')' || ch === '|') {
      if (top) {
        throw new AlphabetError(`${repr(ch)} outside a group`, pos);
      }
      break;
    }
    if (FORBIDDEN.includes(ch)) {
      throw new AlphabetError(`construct ${repr(ch)} is not admissible`, pos);
    }
    if (ch === '?') {
      if (!quantifiable) {
        throw new AlphabetError("'?' follows nothing", pos);
      }
      parts.push(ch);
      quantifiable = false;
      pos += 1;
    } else if (ch === '{') {
      if (!quantifiable) {
        throw new AlphabetError('count follows nothing', pos);
      }
      COUNT_RE.lastIndex = pos;
      const match = COUNT_RE.exec(expr);
      if (match === null) {
        throw new AlphabetError('count {n} or {n,m} expected', pos);
      }
      if (match[2] !== undefined && parseInt(match[2], 10) < parseInt(match[1], 10)) {
        throw new AlphabetError('count {n,m} with m < n', pos);
      }
      parts.push(match[0]);
      quantifiable = false;
      pos = COUNT_RE.lastIndex;
    } else if (']}-,'.includes(ch)) {
      throw new AlphabetError(`${repr(ch)} must be escaped`, pos);
    } else if (ch === '\\') {
      parts.push(escapeChar(escaped(expr, pos), SPECIAL));
      quantifiable = true;
      pos += 2;
    } else if (ch === '.') {
      parts.push(ANY_CHAR);
      quantifiable = true;
      pos += 1;
    } else if (ch === '[') {
      const [source, next] = charClass(expr, pos + 1);
      parts.push(source);
      quantifiable = true;
      pos = next;
    } else if (ch === '(') {
      const [source, next] = group(expr, pos + 1);
      parts.push(source);
      quantifiable = true;
      pos = next;
    } else {
      parts.push(escapeChar(ch, SPECIAL));
      quantifiable = true;
      pos += 1;
    }
  }
  return [parts.join(''), pos];
}

/** The character the escape at pos denotes. */
function escaped(expr: string, pos: number): string {
  if (pos + 1 >= expr.length || !ESCAPABLE.includes(expr[pos + 1])) {
    throw new AlphabetError('unknown escape', pos);
  }
  return expr[pos + 1];
}

function group(expr: string, start: number): [string, number] {
  const branches: string[] = [];
  let pos = start;
  for (;;) {
    const [source, next] = sequence(expr, pos, false);
    if (!source) {
      throw new AlphabetError('empty alternative', next);
    }
    branches.push(source);
    if (next >= expr.length) {
      throw new AlphabetError("unbalanced '('", start - 1);
    }
    pos = next + 1;
    if (expr[next] === ')') {
      return [`(?:${branches.join('|')})`, pos];
    }
  }
}

/** One character of a class and the position after it. */
function classItem(expr: string, pos: number): [string, number] {
  const ch = expr[pos];
  if (ch === '\\') {
    return [escaped(expr, pos), pos + 2];
  }
  if ('[^-'.includes(ch)) {
    throw new AlphabetError(`${repr(ch)} must be escaped`, pos);
  }
  return [ch, pos + 1];
}

function charClass(expr: string, start: number): [string, number] {
  const items: string[] = [];
  let pos = start;
  while (pos < expr.length && expr[pos] !== ']') {
    const [low, next] = classItem(expr, pos);
    pos = next;
    if (pos + 1 < expr.length && expr[pos] === '-' && expr[pos + 1] !== ']') {
      const [high, after] = classItem(expr, pos + 1);
      pos = after;
      if (compareText(high, low) < 0) {
        throw new AlphabetError('range out of order', pos - 1);
      }
      items.push(escapeChar(low, CLASS_SPECIAL) + '-' + escapeChar(high, CLASS_SPECIAL));
    } else {
      items.push(escapeChar(low, CLASS_SPECIAL));
    }
  }
  if (pos >= expr.length) {
    throw new AlphabetError("unbalanced '['", start - 1);
  }
  if (!items.length) {
    throw new AlphabetError('empty character class', start - 1);
  }
  return [`[${items.join('')}]`, pos + 1];
}
