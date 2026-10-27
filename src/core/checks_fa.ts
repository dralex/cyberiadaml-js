/* -----------------------------------------------------------------------------
 * The Cyberiada State Machine JavaScript Library
 *
 * The EXT-FA rules: deterministic finite automaton documents (type/ fa)
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

import { ENTRY, EVENT, Block } from './actions';
import * as alphabet from './alphabet';
import { ERROR } from './findings';
import {
  AnyNode,
  Comment,
  State,
  StateMachine,
  SubmachineState,
  Transition,
  Vertex,
} from './model';
import { Context, declare, rule } from './rules';
import { repr } from './util';

const INITIAL = 'initial';
const FINAL = 'final';
const FA_VERTICES = [INITIAL, FINAL];
const EOF = alphabet.EOF;
const BLOCK = 'block';
const FORMAL = 'formal';

// Every rule below applies to an FA document only: the model recognises the metadata
// parameter type/ fa (Document.isFa), the rules return at once otherwise.
declare(
  'fa-type',
  'CGML-FA-5-1',
  3,
  ERROR,
  'type/ fa in the metadata selects the EXT-FA rules',
  'recognised by the model (Document.isFa), never reported',
);

function fa(ctx: Context): boolean {
  return ctx.model !== null && ctx.model.isFa;
}

type Parent = State | SubmachineState | null;

/** The [node, parent state] pairs of the machine, region children included. */
function* nodes(machine: StateMachine): Generator<[AnyNode, Parent]> {
  function* walk(children: AnyNode[], parent: Parent): Generator<[AnyNode, Parent]> {
    for (const child of children) {
      yield [child, parent];
      if (child instanceof State || child instanceof SubmachineState) {
        for (const region of child.regions) {
          yield* walk(region.children, child);
        }
      }
    }
  }
  yield* walk(machine.children, null);
}

function index(machine: StateMachine): Map<string | null, AnyNode> {
  const table = new Map<string | null, AnyNode>();
  for (const [node] of nodes(machine)) {
    table.set(node.id, node);
  }
  return table;
}

function kind(node: AnyNode | undefined): string | null {
  return node instanceof Vertex ? (node.kind ?? '').trim() : null;
}

function events(transition: Transition): Block[] {
  return transition.blocks.filter((b) => b.kind === EVENT);
}

/** The event name of a single-event transition, null otherwise. */
function event(transition: Transition): string | null {
  const blocks = events(transition);
  return blocks.length === 1 ? blocks[0].trigger.trim() : null;
}

/** The transitions of the automaton: those leaving a state. */
function* stateTransitions(
  machine: StateMachine,
  table: Map<string | null, AnyNode>,
): Generator<Transition> {
  for (const transition of machine.transitions) {
    if (table.get(transition.source) instanceof State) {
      yield transition;
    }
  }
}

function* alphabetComments(machine: StateMachine): Generator<[Comment, Parent]> {
  for (const [node, parent] of nodes(machine)) {
    if (node instanceof Comment && node.name !== null && alphabet.NAMES.includes(node.name)) {
      yield [node, parent];
    }
  }
}

/** The parsed input and output alphabets, null when not declared. */
function alphabets(machine: StateMachine): [alphabet.Alphabet | null, alphabet.Alphabet | null] {
  let inputs: alphabet.Alphabet | null = null;
  let outputs: alphabet.Alphabet | null = null;
  for (const [node] of alphabetComments(machine)) {
    const name = node.name as string;
    if (alphabet.INPUT_NAMES.includes(name)) {
      inputs = inputs ?? alphabet.parse(name, node.body);
    } else {
      outputs = outputs ?? alphabet.parse(name, node.body);
    }
  }
  return [inputs, outputs];
}

function symbolLines(block: Block): string[] {
  return block.behaviour.map((line) => line.trim());
}

// L3 ----------------------------------------------------------------------

rule(
  'fa-event-propagation',
  'CGML-FA-5-3',
  3,
  ERROR,
  'an FA document propagates no events: eventPropagation absent or block',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    const value = ctx.doc.param('eventPropagation');
    if (value !== null && value.trim() !== BLOCK) {
      ctx.emit(
        'fa-event-propagation',
        `eventPropagation ${repr(value.trim())} in an FA document, block expected`,
        ctx.doc.metaComment?.elem ?? null,
      );
    }
  },
);

rule(
  'fa-state-behaviour',
  'CGML-FA-3.1-1',
  3,
  ERROR,
  'an FA state holds at most a one-line entry/ block, the output symbol',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      for (const [node] of nodes(machine)) {
        if (!(node instanceof State)) {
          continue;
        }
        for (const block of node.blocks) {
          if (block.kind !== ENTRY) {
            ctx.emit(
              'fa-state-behaviour',
              `state ${repr(node.id)} has a ${block.kind} block; only entry/ is ` +
                'admissible in an FA diagram',
              node.elem,
            );
          } else if (symbolLines(block).length !== 1) {
            ctx.emit(
              'fa-state-behaviour',
              `the entry/ block of state ${repr(node.id)} has ${block.behaviour.length} lines, ` +
                'one output symbol expected',
              node.elem,
            );
          }
        }
      }
    }
  },
);

rule(
  'fa-initial-transition',
  'CGML-FA-3.2-2',
  3,
  ERROR,
  'the transition from an initial pseudostate has no event, guard, action',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      const table = index(machine);
      for (const transition of machine.transitions) {
        if (kind(table.get(transition.source)) === INITIAL && transition.blocks.length) {
          ctx.emit(
            'fa-initial-transition',
            `transition ${repr(transition.id)} from the initial pseudostate carries a label`,
            transition.elem,
          );
        }
      }
    }
  },
);

rule(
  'fa-transition-label',
  'CGML-FA-3.4-1',
  3,
  ERROR,
  'an FA transition carries one symbol: no guard, no event parameters',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      for (const transition of stateTransitions(machine, index(machine))) {
        const blocks = events(transition);
        if (blocks.length !== 1) {
          ctx.emit(
            'fa-transition-label',
            `transition ${repr(transition.id)} carries ${blocks.length} events, exactly one ` +
              'symbol expected',
            transition.elem,
          );
          continue;
        }
        const block = blocks[0];
        const trigger = block.trigger.trim();
        if (!trigger || trigger.includes('\n')) {
          ctx.emit(
            'fa-transition-label',
            `transition ${repr(transition.id)} has no single-line symbol`,
            transition.elem,
          );
        }
        if (block.guard !== null) {
          ctx.emit(
            'fa-transition-label',
            `transition ${repr(transition.id)} carries a guard`,
            transition.elem,
          );
        }
        if (block.param !== null) {
          ctx.emit(
            'fa-transition-label',
            `transition ${repr(transition.id)} carries the parameter ${repr(block.param)}`,
            transition.elem,
          );
        }
      }
    }
  },
);

rule(
  'fa-transition-action',
  'CGML-FA-3.4-2',
  3,
  ERROR,
  'an FA transition action is at most one line, the output symbol',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      for (const transition of stateTransitions(machine, index(machine))) {
        for (const block of events(transition)) {
          if (block.behaviour.length > 1) {
            ctx.emit(
              'fa-transition-action',
              `transition ${repr(transition.id)} has ${block.behaviour.length} action lines, ` +
                'one output symbol expected',
              transition.elem,
            );
          }
        }
      }
    }
  },
);

rule(
  'fa-symbol-reserved',
  'CGML-FA-3.4-3',
  3,
  ERROR,
  'an FA symbol is no reserved word and no reserved event name',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    const check = (symbol: string, where: string, elem: Transition['elem']): void => {
      if (alphabet.RESERVED_SYMBOLS.includes(symbol)) {
        ctx.emit('fa-symbol-reserved', `reserved name ${repr(symbol)} used as ${where}`, elem);
      }
    };
    for (const machine of ctx.doc.machines) {
      for (const [node] of nodes(machine)) {
        if (node instanceof State) {
          for (const block of node.blocks) {
            for (const line of symbolLines(block)) {
              check(line, `the output symbol of state ${repr(node.id)}`, node.elem);
            }
          }
        } else if (
          node instanceof Comment &&
          node.name !== null &&
          alphabet.NAMES.includes(node.name) &&
          !node.name.endsWith(alphabet.RE_SUFFIX)
        ) {
          for (const line of alphabet.parse(node.name, node.body).symbols) {
            check(line, `a symbol of ${node.name}`, node.elem);
          }
        }
      }
      for (const transition of stateTransitions(machine, index(machine))) {
        for (const block of events(transition)) {
          const trigger = block.trigger.trim();
          if (trigger !== EOF) {
            check(trigger, `the symbol of transition ${repr(transition.id)}`, transition.elem);
          }
          for (const line of symbolLines(block)) {
            check(line, `the output symbol of transition ${repr(transition.id)}`, transition.elem);
          }
        }
      }
    }
  },
);

rule(
  'fa-alphabet-syntax',
  'CGML-FA-4-2',
  3,
  ERROR,
  'an alphabet comment lists one symbol or restricted pattern per line',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      for (const [node] of alphabetComments(machine)) {
        const name = node.name as string;
        for (const [line, message] of alphabet.parse(name, node.body).errors) {
          ctx.emit('fa-alphabet-syntax', `${name}: ${message} (value line ${line + 1})`, node.elem);
        }
      }
    }
  },
);

// L4 ----------------------------------------------------------------------

rule(
  'fa-single-machine',
  'CGML-FA-5-2',
  4,
  ERROR,
  'an FA document contains one state machine',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    const machines = ctx.doc.machines;
    if (machines.length !== 1) {
      ctx.emit(
        'fa-single-machine',
        `FA document with ${machines.length} state machines`,
        machines[machines.length - 1].elem,
      );
    }
  },
);

rule(
  'fa-element-set',
  'CGML-FA-3-1',
  4,
  ERROR,
  'an FA diagram uses states, initial, final, transitions, comments only',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      for (const [node] of nodes(machine)) {
        if (node instanceof Vertex && !FA_VERTICES.includes(kind(node) ?? '')) {
          ctx.emit(
            'fa-element-set',
            `vertex ${repr(node.id)} of kind ${repr(kind(node))}`,
            node.elem,
          );
        } else if (node instanceof SubmachineState) {
          ctx.emit('fa-element-set', `submachine state ${repr(node.id)}`, node.elem);
        } else if (node instanceof State && node.collapsed) {
          ctx.emit(
            'fa-element-set',
            `collapsed decomposition block on state ${repr(node.id)}`,
            node.elem,
          );
        }
      }
    }
  },
);

rule(
  'fa-composite',
  'CGML-FA-3.1.1-1',
  4,
  ERROR,
  'an FA composite state has one region and no entry/ block',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      for (const [node] of nodes(machine)) {
        if (!(node instanceof State) || !node.regions.length) {
          continue;
        }
        if (node.regions.length !== 1) {
          ctx.emit(
            'fa-composite',
            `composite state ${repr(node.id)} has ${node.regions.length} regions`,
            node.elem,
          );
        }
        if (node.blocks.some((b) => b.kind === ENTRY)) {
          ctx.emit(
            'fa-composite',
            `composite state ${repr(node.id)} has an entry/ block`,
            node.elem,
          );
        }
      }
    }
  },
);

rule(
  'fa-composite-initial',
  'CGML-FA-3.1.1-2',
  4,
  ERROR,
  'a composite state entered by a transition contains an initial',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      const table = index(machine);
      const entered = new Set<string | null>();
      for (const transition of machine.transitions) {
        const target = table.get(transition.target);
        if (target instanceof State && target.regions.length && !entered.has(target.id)) {
          entered.add(target.id);
          const hasInitial = target.regions.some((region) =>
            region.children.some((n) => kind(n) === INITIAL),
          );
          if (!hasInitial) {
            ctx.emit(
              'fa-composite-initial',
              `composite state ${repr(target.id)} is entered by transition ` +
                `${repr(transition.id)} but contains no initial pseudostate`,
              target.elem,
            );
          }
        }
      }
    }
  },
);

rule(
  'fa-deterministic',
  'CGML-FA-3.1.1-3',
  4,
  ERROR,
  'a state has at most one own transition per symbol',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      const seen = new Map<string, Transition>();
      for (const transition of stateTransitions(machine, index(machine))) {
        const name = event(transition);
        if (name === null) {
          continue;
        }
        const key = `${transition.source}\u0000${name}`;
        const first = seen.get(key);
        if (first === undefined) {
          seen.set(key, transition);
        } else {
          ctx.emit(
            'fa-deterministic',
            `transitions ${repr(first.id)} and ${repr(transition.id)} leave state ` +
              `${repr(transition.source)} by the same symbol ${repr(name)}`,
            transition.elem,
          );
        }
      }
    }
  },
);

rule(
  'fa-top-initial',
  'CGML-FA-3.2-1',
  4,
  ERROR,
  'the top level of an FA state machine holds one initial pseudostate',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      const count = machine.children.filter((n) => kind(n) === INITIAL).length;
      if (count !== 1) {
        ctx.emit(
          'fa-top-initial',
          `state machine ${repr(machine.id)} has ${count} top-level initial pseudostates`,
          machine.elem,
        );
      }
    }
  },
  ['CGML-6.4-4-1', 'CGML-6.4-4-2'],
);

rule(
  'fa-final-top-level',
  'CGML-FA-3.3-1',
  4,
  ERROR,
  'FA final states sit at the top level of the state machine',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      for (const [node, parent] of nodes(machine)) {
        if (kind(node) === FINAL && parent !== null) {
          ctx.emit(
            'fa-final-top-level',
            `final state ${repr(node.id)} inside composite state ${repr(parent.id)}`,
            node.elem,
          );
        }
      }
    }
  },
);

rule(
  'fa-eof-final',
  'CGML-FA-3.3-2',
  4,
  ERROR,
  'a transition into a final state carries EOF and EOF leads to a final',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      const table = index(machine);
      for (const transition of machine.transitions) {
        const isEof =
          kind(table.get(transition.source)) === INITIAL ? false : event(transition) === EOF;
        const toFinal = kind(table.get(transition.target)) === FINAL;
        if (isEof && !toFinal) {
          ctx.emit(
            'fa-eof-final',
            `EOF transition ${repr(transition.id)} targets ${repr(transition.target)}, ` +
              'not a final state',
            transition.elem,
          );
        } else if (toFinal && !isEof) {
          ctx.emit(
            'fa-eof-final',
            `transition ${repr(transition.id)} into the final state ` +
              `${repr(transition.target)} carries no EOF`,
            transition.elem,
          );
        }
      }
    }
  },
);

rule(
  'fa-alphabet-comments',
  'CGML-FA-4-1',
  4,
  ERROR,
  'one input and one output alphabet comment, formal, at the top level',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      const seen = new Map<string, Comment>();
      for (const [node, parent] of alphabetComments(machine)) {
        const name = node.name as string;
        if ((node.kind ?? '').trim() !== FORMAL) {
          ctx.emit(
            'fa-alphabet-comments',
            `alphabet comment ${repr(node.id)} (${name}) is not formal`,
            node.elem,
          );
        }
        if (parent !== null) {
          ctx.emit(
            'fa-alphabet-comments',
            `alphabet comment ${repr(node.id)} (${name}) inside state ${repr(parent.id)}, ` +
              'the top level expected',
            node.elem,
          );
        }
        const which = alphabet.INPUT_NAMES.includes(name) ? 'input' : 'output';
        const first = seen.get(which);
        if (first === undefined) {
          seen.set(which, node);
        } else {
          ctx.emit(
            'fa-alphabet-comments',
            `second ${which} alphabet comment ${repr(node.id)} (${name}) after ` +
              `${repr(first.id)} (${first.name})`,
            node.elem,
          );
        }
      }
    }
  },
);

rule(
  'fa-alphabet-membership',
  'CGML-FA-4-3',
  4,
  ERROR,
  'the symbols of the diagram belong to the declared alphabets',
  (ctx) => {
    if (!fa(ctx)) {
      return;
    }
    for (const machine of ctx.doc.machines) {
      let [inputs, outputs] = alphabets(machine);
      if (inputs !== null && inputs.errors.length) {
        inputs = null;
      }
      if (outputs !== null && outputs.errors.length) {
        outputs = null;
      }
      if (inputs === null && outputs === null) {
        continue;
      }
      const check = (
        table: alphabet.Alphabet | null,
        symbol: string,
        where: string,
        elem: Transition['elem'],
      ): void => {
        if (table !== null && !table.contains(symbol)) {
          ctx.emit(
            'fa-alphabet-membership',
            `${where} ${repr(symbol)} is not in ${table.name}`,
            elem,
          );
        }
      };
      for (const [node] of nodes(machine)) {
        if (node instanceof State) {
          for (const block of node.blocks) {
            for (const line of symbolLines(block)) {
              check(outputs, line, `the output symbol of state ${repr(node.id)}`, node.elem);
            }
          }
        }
      }
      for (const transition of stateTransitions(machine, index(machine))) {
        for (const block of events(transition)) {
          const trigger = block.trigger.trim();
          if (trigger !== EOF) {
            check(
              inputs,
              trigger,
              `the symbol of transition ${repr(transition.id)}`,
              transition.elem,
            );
          }
          for (const line of symbolLines(block)) {
            check(
              outputs,
              line,
              `the output symbol of transition ${repr(transition.id)}`,
              transition.elem,
            );
          }
        }
      }
    }
  },
);
