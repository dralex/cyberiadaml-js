/* -----------------------------------------------------------------------------
 * The Cyberiada State Machine JavaScript Library
 *
 * The EXT-FA rule tests: finite automaton documents
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

import { META_NODE, minimal } from './docbuilder';

import { runDocument } from '../../src/core/reader';
import { Context } from '../../src/core/rules';

const FA_META = META_NODE.replace('standardVersion/ 1.0', 'standardVersion/ 1.0\n\ntype/ fa');

const HEAD = `\
  <graph id="G" edgedefault="directed">
    <data key="dStateMachine"/>
    <data key="dName">Automaton</data>
`;

const NODES = `\
    <node id="init">
      <data key="dVertex">initial</data>
    </node>
    <node id="q0">
      <data key="dName">q0</data>
    </node>
    <node id="q1">
      <data key="dName">q1</data>
      <data key="dData">entry/
1</data>
    </node>
    <node id="fin">
      <data key="dVertex">final</data>
    </node>
`;

const EDGES = `\
    <edge id="init-q0" source="init" target="q0"/>
    <edge id="q0-q1" source="q0" target="q1">
      <data key="dData">a/
0</data>
    </edge>
    <edge id="q1-q1" source="q1" target="q1">
      <data key="dData">b/</data>
    </edge>
    <edge id="q1-fin" source="q1" target="fin">
      <data key="dData">EOF/</data>
    </edge>
`;

function composite(inner: string): string {
  return `\
    <node id="c0">
      <data key="dName">C</data>
      <graph id="c0:" edgedefault="directed">
        <data key="dRegion"/>
${inner}\
        <node id="c1">
          <data key="dName">c1</data>
        </node>
      </graph>
    </node>
`;
}

const INNER_INITIAL = `\
        <node id="c0init">
          <data key="dVertex">initial</data>
        </node>
`;

// edges sit in the state machine graph (CGML-6.5-3), the region holds nodes
const INNER_EDGE = '    <edge id="c0init-c1" source="c0init" target="c1"/>\n';
const NESTED = NODES + composite(INNER_INITIAL);

const SECOND_MACHINE = `\
  <graph id="G2" edgedefault="directed">
    <data key="dStateMachine"/>
    <data key="dName">Second</data>
    <node id="g2n0">
      <data key="dName">Idle</data>
    </node>
  </graph>
`;

function comment(name: string, body: string, ident = 'alpha', kind = 'formal'): string {
  return (
    `    <node id="${ident}">\n      <data key="dNote">${kind}</data>\n` +
    `      <data key="dName">${name}</data>\n` +
    `      <data key="dData">${body}</data>\n    </node>\n`
  );
}

interface Pieces {
  nodes?: string;
  edges?: string;
  meta?: string;
  extra?: string;
}

function fa(pieces: Pieces = {}): Uint8Array {
  const { nodes = NODES, edges = EDGES, meta = FA_META, extra = '' } = pieces;
  return minimal({ keys: '', machines: HEAD + meta + nodes + edges + '  </graph>\n' + extra });
}

function run(data: Uint8Array): Context {
  return runDocument(data, 'test.graphml');
}

function errors(ctx: Context): string[] {
  return ctx.report.findings.filter((f) => f.severity === 'ERROR').map((f) => f.rule);
}

function faErrors(ctx: Context): string[] {
  return errors(ctx).filter((name) => name.startsWith('fa-'));
}

const ENTER_C =
  '    <edge id="q0-c0" source="q0" target="c0">\n      <data key="dData">c/</data>\n    </edge>\n';

test('fa document clean', () => {
  const ctx = run(fa());
  expect(ctx.report.findings).toEqual([]);
  expect(ctx.doc.isFa).toBe(true);
});

test('fa rules silent without type fa', () => {
  const edges = EDGES.replace('a/\n0', 'a [x] propagate/\n0\n1');
  const ctx = run(fa({ edges, meta: META_NODE }));
  expect(ctx.doc.isFa).toBe(false);
  expect(faErrors(ctx)).toEqual([]);
});

test('type value is stripped', () => {
  const meta = META_NODE.replace('standardVersion/ 1.0', 'standardVersion/ 1.0\n\ntype/  fa ');
  expect(run(fa({ meta })).doc.isFa).toBe(true);
});

test('event propagation', () => {
  const meta = FA_META.replace('type/ fa', 'type/ fa\n\neventPropagation/ block');
  expect(faErrors(run(fa({ meta })))).toEqual([]);
  expect(faErrors(run(fa({ meta: meta.replace('/ block', '/ propagate') })))).toEqual([
    'fa-event-propagation',
  ]);
});

test('single machine', () => {
  expect(errors(run(fa({ extra: SECOND_MACHINE })))).toContain('fa-single-machine');
});

test('element set', () => {
  const choice = '    <node id="ch">\n      <data key="dVertex">choice</data>\n    </node>\n';
  expect(errors(run(fa({ nodes: NODES + choice })))).toContain('fa-element-set');
  const collapsed = NESTED.replace(
    '<data key="dName">C</data>',
    '<data key="dName">C</data>\n      <data key="dCollapsed"/>',
  );
  expect(errors(run(fa({ nodes: collapsed, edges: EDGES + INNER_EDGE })))).toContain(
    'fa-element-set',
  );
});

test('state behaviour', () => {
  expect(errors(run(fa({ nodes: NODES.replace('entry/\n1', 'exit/\n1') })))).toContain(
    'fa-state-behaviour',
  );
  expect(errors(run(fa({ nodes: NODES.replace('entry/\n1', 'entry/\n1\n2') })))).toContain(
    'fa-state-behaviour',
  );
  expect(errors(run(fa({ nodes: NODES.replace('entry/\n1', 'entry/\n1\n\nc/ x') })))).toContain(
    'fa-state-behaviour',
  );
});

test('composite accepted with one region and initial', () => {
  const ctx = run(fa({ nodes: NESTED, edges: EDGES + INNER_EDGE + ENTER_C }));
  expect(ctx.report.findings).toEqual([]);
});

test('composite entry and regions', () => {
  const withEntry = NESTED.replace(
    '<data key="dName">C</data>',
    '<data key="dName">C</data>\n      <data key="dData">entry/\n1</data>',
  );
  expect(errors(run(fa({ nodes: withEntry, edges: EDGES + INNER_EDGE })))).toContain(
    'fa-composite',
  );
  const second =
    '        <graph id="c0:2" edgedefault="directed">\n' +
    '          <data key="dRegion"/>\n        </graph>\n';
  const two = NESTED.replace(
    '      </graph>\n    </node>',
    '      </graph>\n' + second + '    </node>',
  );
  expect(errors(run(fa({ nodes: two, edges: EDGES + INNER_EDGE })))).toContain('fa-composite');
});

test('composite entered without initial', () => {
  let ctx = run(fa({ nodes: NODES + composite(''), edges: EDGES + ENTER_C }));
  expect(errors(ctx)).toContain('fa-composite-initial');
  ctx = run(fa({ nodes: NODES + composite('') }));
  expect(errors(ctx)).not.toContain('fa-composite-initial');
});

test('deterministic', () => {
  const loop = (symbol: string): string =>
    `    <edge id="q0-q0" source="q0" target="q0">\n      <data key="dData">${symbol}/</data>\n    </edge>\n`;
  expect(errors(run(fa({ edges: EDGES + loop('a') })))).toContain('fa-deterministic');
  expect(errors(run(fa({ edges: EDGES + loop('c') })))).not.toContain('fa-deterministic');
});

test('child transition shadows the parent', () => {
  const edges =
    EDGES +
    INNER_EDGE +
    ENTER_C +
    '    <edge id="c0-q0" source="c0" target="q0">\n      <data key="dData">a/</data>\n    </edge>\n' +
    '    <edge id="c1-q1" source="c1" target="q1">\n      <data key="dData">a/</data>\n    </edge>\n';
  const ctx = run(fa({ nodes: NESTED, edges }));
  expect(ctx.report.findings).toEqual([]);
});

test('top initial', () => {
  const nodes = NODES.replace(
    '    <node id="init">\n      <data key="dVertex">initial</data>\n    </node>\n',
    '',
  );
  const edges = EDGES.replace('    <edge id="init-q0" source="init" target="q0"/>\n', '');
  expect(errors(run(fa({ nodes, edges })))).toContain('fa-top-initial');
});

test('initial transition label', () => {
  const edges = EDGES.replace(
    '<edge id="init-q0" source="init" target="q0"/>',
    '<edge id="init-q0" source="init" target="q0">\n      <data key="dData">a/</data>\n    </edge>',
  );
  expect(errors(run(fa({ edges })))).toContain('fa-initial-transition');
});

test('final top level', () => {
  const nodes = NESTED.replace('<data key="dName">c1</data>', '<data key="dVertex">final</data>');
  expect(errors(run(fa({ nodes })))).toContain('fa-final-top-level');
});

test('eof final', () => {
  expect(errors(run(fa({ edges: EDGES.replace('b/', 'EOF/') })))).toContain('fa-eof-final');
  const symbolToFinal = EDGES.replace(
    'target="fin">\n      <data key="dData">EOF/',
    'target="fin">\n      <data key="dData">c/',
  );
  expect(errors(run(fa({ edges: symbolToFinal })))).toContain('fa-eof-final');
  expect(errors(run(fa({ edges: EDGES.replace('target="q0"/>', 'target="fin"/>') })))).toContain(
    'fa-eof-final',
  );
});

test.each(['a [x]/', 'a propagate/', 'a/\n\nb/', '/', '[x]/', ''])(
  'transition label %j rejected',
  (label) => {
    expect(errors(run(fa({ edges: EDGES.replace('b/', label) })))).toContain('fa-transition-label');
  },
);

test('transition action', () => {
  expect(errors(run(fa({ edges: EDGES.replace('a/\n0', 'a/\n0\n1') })))).toContain(
    'fa-transition-action',
  );
});

test('symbol reserved', () => {
  expect(errors(run(fa({ edges: EDGES.replace('b/', 'ANY/') })))).toContain('fa-symbol-reserved');
  expect(errors(run(fa({ edges: EDGES.replace('a/\n0', 'a/\nelse') })))).toContain(
    'fa-symbol-reserved',
  );
  expect(errors(run(fa({ nodes: NODES.replace('entry/\n1', 'entry/\nEOF') })))).toContain(
    'fa-symbol-reserved',
  );
  expect(errors(run(fa({ nodes: NODES + comment('FA_OUTPUT', '0\nblock') })))).toContain(
    'fa-symbol-reserved',
  );
});

test('alphabet comments', () => {
  let nodes = NODES + comment('FA_INPUT', 'a\nb') + comment('FA_INPUT_RE', '[ab]', 'beta');
  expect(errors(run(fa({ nodes })))).toContain('fa-alphabet-comments');
  nodes = NODES + comment('FA_INPUT', 'a\nb', 'alpha', 'informal');
  expect(errors(run(fa({ nodes })))).toContain('fa-alphabet-comments');
  const inner = NESTED.replace(
    '        <node id="c1">',
    comment('FA_INPUT', 'a\nb\nc').split('\n    ').join('\n        ') + '        <node id="c1">',
  );
  expect(errors(run(fa({ nodes: inner, edges: EDGES + INNER_EDGE })))).toContain(
    'fa-alphabet-comments',
  );
});

test('alphabet syntax', () => {
  expect(errors(run(fa({ nodes: NODES + comment('FA_INPUT_RE', '[ab]\nc*') })))).toContain(
    'fa-alphabet-syntax',
  );
  expect(errors(run(fa({ nodes: NODES + comment('FA_OUTPUT', '0\n\n1') })))).toContain(
    'fa-alphabet-syntax',
  );
});

test('alphabet membership', () => {
  let nodes = NODES + comment('FA_INPUT', 'a\nb') + comment('FA_OUTPUT_RE', '[01]', 'beta');
  expect(faErrors(run(fa({ nodes })))).toEqual([]);
  nodes = NODES + comment('FA_INPUT', 'a');
  expect(errors(run(fa({ nodes })))).toEqual(['fa-alphabet-membership']);
  nodes = NODES + comment('FA_OUTPUT', '1');
  expect(errors(run(fa({ nodes })))).toEqual(['fa-alphabet-membership']);
  nodes = NODES + comment('FA_OUTPUT_RE', '[1]*');
  expect(errors(run(fa({ nodes })))).not.toContain('fa-alphabet-membership');
});
