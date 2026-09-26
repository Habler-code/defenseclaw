// Trust-zone grouping for <Flow>. Renders flows to static markup, the
// same SSR path the docs build uses, and checks the zone geometry the
// engine promises in components/diagram/AUTHORING.md.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { Edge, Flow, Node, Zone } from '../components/diagram/flow';
import {
  ARTICLE_WIDTH_HARD_LIMIT,
  ZONE_TONE_STYLE,
  type DiagramKind,
  type ZoneTone,
} from '../components/diagram/shared';

interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface Rendered {
  html: string;
  width: number;
  height: number;
  frames: Map<string, Rect & { tone: string }>;
  badges: Map<string, Rect & { text: string }>;
  // Card rects in render order, which is the order the Nodes appear in
  // the Flow's children.
  cards: Rect[];
}

function attr(tag: string, name: string): string {
  const match = new RegExp(`\\b${name}="([^"]*)"`).exec(tag);
  assert.ok(match, `missing ${name} in ${tag}`);
  return match[1];
}

function rectOf(tag: string): Rect {
  return {
    x: Number(attr(tag, 'x')),
    y: Number(attr(tag, 'y')),
    width: Number(attr(tag, 'width')),
    height: Number(attr(tag, 'height')),
  };
}

function render(flow: ReactNode): Rendered {
  const html = renderToStaticMarkup(flow);
  const figure = /<figure\b[^>]*>/.exec(html);
  assert.ok(figure, 'no diagram figure rendered');
  const frames = new Map<string, Rect & { tone: string }>();
  for (const [tag] of html.matchAll(/<rect class="fd-flow-zone"[^>]*>/g)) {
    frames.set(attr(tag, 'data-zone'), { ...rectOf(tag), tone: attr(tag, 'data-zone-tone') });
  }
  const badges = new Map<string, Rect & { text: string }>();
  for (const [badge] of html.matchAll(/<foreignObject class="fd-flow-zone-badge"[\s\S]*?<\/foreignObject>/g)) {
    const tag = badge.slice(0, badge.indexOf('>') + 1);
    badges.set(attr(tag, 'data-zone'), {
      ...rectOf(tag),
      text: badge.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim(),
    });
  }
  const cards = [...html.matchAll(/<g class="fd-flow-node"[^>]*><rect [^>]*>/g)].map(([match]) =>
    rectOf(match.slice(match.indexOf('<rect'))),
  );
  return {
    html,
    width: Number(attr(figure[0], 'data-natural-width')),
    height: Number(attr(figure[0], 'data-natural-height')),
    frames,
    badges,
    cards,
  };
}

const intersects = (a: Rect, b: Rect) =>
  a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;

// Per-diagram ids differ between renders; nothing else should.
const normalizeIds = (html: string) => html.replace(/fd-flow-[0-9a-z]+/g, 'fd-flow-#');

// Geometry every zoned Flow must satisfy. `zoneOf[i]` is the zone id
// of the i-th Node (undefined when unzoned).
function zoneProblems(rendered: Rendered, zoneOf: (string | undefined)[]): string[] {
  const problems: string[] = [];
  const { width, height, frames, badges, cards } = rendered;
  if (cards.length !== zoneOf.length) problems.push(`rendered ${cards.length} cards, expected ${zoneOf.length}`);
  const populated = new Set(zoneOf.filter((id): id is string => id !== undefined));
  if (frames.size !== populated.size) problems.push(`rendered ${frames.size} zones, expected ${populated.size}`);

  const frameList = [...frames.entries()];
  frameList.forEach(([id, frame], i) => {
    for (const [otherId, other] of frameList.slice(i + 1)) {
      if (intersects(frame, other)) problems.push(`zones ${id} and ${otherId} overlap`);
    }
    const badge = badges.get(id);
    if (!badge) {
      problems.push(`zone ${id} has no badge`);
      return;
    }
    if (frame.x < 0 || frame.y < 0 || frame.x + frame.width > width || frame.y + frame.height > height) {
      problems.push(`zone ${id} leaves the ${width}x${height} viewBox`);
    }
    if (badge.y < 0 || badge.x < frame.x || badge.x + badge.width > frame.x + frame.width + 0.01) {
      problems.push(`badge ${id} leaves its zone or the viewBox`);
    }
    if (Math.abs(badge.y + badge.height / 2 - frame.y) > 0.01) problems.push(`badge ${id} is off the top border`);
  });

  cards.forEach((card, i) => {
    for (const [id, frame] of frames) {
      if (id === zoneOf[i]) {
        const inset = {
          left: card.x - frame.x,
          right: frame.x + frame.width - (card.x + card.width),
          top: card.y - frame.y,
          bottom: frame.y + frame.height - (card.y + card.height),
        };
        const EPSILON = 0.01;
        if (
          inset.left < 16 - EPSILON ||
          inset.right < 16 - EPSILON ||
          inset.top < 24 - EPSILON ||
          inset.bottom < 16 - EPSILON
        ) {
          problems.push(`node #${i} is not padded inside zone ${id}: ${JSON.stringify(inset)}`);
        }
      } else if (intersects(card, frame)) {
        problems.push(`node #${i} intrudes on zone ${id}`);
      }
    }
    for (const [id, badge] of badges) {
      if (intersects(card, badge)) problems.push(`badge ${id} overlaps node #${i}`);
    }
  });
  return problems;
}

const THREAT_MODEL_ZONES = [
  { id: 'z4', label: 'Z4 · User session (untrusted)', tone: 'untrusted' },
  { id: 'z5', label: 'Z5 · External', tone: 'external' },
  { id: 'z1', label: 'Z1 · Privileged services (LocalSystem · root)', tone: 'privileged' },
  { id: 'z0', label: 'Z0 · Trusted platform & admin', tone: 'trusted' },
  { id: 'z2', label: 'Z2 · Restricted service identity', tone: 'restricted' },
  { id: 'z3', label: 'Z3 · Admin-owned state', tone: 'protected' },
] as const satisfies readonly { id: string; label: string; tone: ZoneTone }[];

const THREAT_MODEL_NODES: { id: string; zone: string; kind?: DiagramKind; text: string }[] = [
  { id: 'agent', zone: 'z4', kind: 'agent', text: 'Agent runtime\nClaude Code · Codex' },
  { id: 'hook', zone: 'z4', kind: 'connector', text: 'Hook CLI' },
  { id: 'registry', zone: 'z5', text: 'Skill registry' },
  { id: 'gateway', zone: 'z1', kind: 'gateway', text: 'defenseclaw-gateway' },
  { id: 'admin', zone: 'z0', kind: 'operator', text: 'Administrator' },
  { id: 'scanner', zone: 'z2', kind: 'connector', text: 'Skill scanner' },
  { id: 'policy', zone: 'z3', kind: 'policy', text: 'Config + policy' },
];

const THREAT_MODEL_EDGES = [
  <Edge key="e1" from="agent" to="hook" label="tool call" />,
  <Edge key="e2" from="hook" to="gateway" label="named pipe" />,
  <Edge key="e3" from="registry" to="gateway" label="skill download" variant="dashed" />,
  <Edge key="e4" from="gateway" to="scanner" label="scan job" />,
  <Edge key="e5" from="gateway" to="policy" label="reads" />,
  <Edge key="e6" from="admin" to="policy" label="edits" />,
];

// The six-zone threat model from AUTHORING.md, with nodes either
// nested in their <Zone> or placed with zone="id".
function threatModel(membership: 'nested' | 'prop') {
  const node = (spec: (typeof THREAT_MODEL_NODES)[number], withZone: boolean) => (
    <Node key={spec.id} id={spec.id} kind={spec.kind} zone={withZone ? spec.zone : undefined}>
      {spec.text}
    </Node>
  );
  const zones = THREAT_MODEL_ZONES.map((zone) =>
    membership === 'nested' ? (
      <Zone key={zone.id} id={zone.id} label={zone.label} tone={zone.tone}>
        {THREAT_MODEL_NODES.filter((spec) => spec.zone === zone.id).map((spec) => node(spec, false))}
      </Zone>
    ) : (
      <Zone key={zone.id} id={zone.id} label={zone.label} tone={zone.tone} />
    ),
  );
  const nodes =
    membership === 'prop'
      ? THREAT_MODEL_ZONES.flatMap((zone) =>
          THREAT_MODEL_NODES.filter((spec) => spec.zone === zone.id).map((spec) => node(spec, true)),
        )
      : [];
  return (
    <Flow direction="TB" caption="Trust zones for a service-mode install">
      {zones}
      {nodes}
      {THREAT_MODEL_EDGES}
    </Flow>
  );
}

// Node order as rendered: zone by zone, in declaration order.
const THREAT_MODEL_ZONE_OF = THREAT_MODEL_ZONES.flatMap((zone) =>
  THREAT_MODEL_NODES.filter((spec) => spec.zone === zone.id).map(() => zone.id),
);

function withWarningsCaptured<T>(fn: () => T): { result: T; warnings: string[] } {
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map(String).join(' '));
  };
  try {
    return { result: fn(), warnings };
  } finally {
    console.warn = original;
  }
}

describe('Flow trust zones', () => {
  it('lays out the six-zone threat model inside the width gate', () => {
    const rendered = render(threatModel('nested'));
    assert.deepEqual(zoneProblems(rendered, THREAT_MODEL_ZONE_OF), []);
    assert.ok(
      rendered.width <= ARTICLE_WIDTH_HARD_LIMIT,
      `natural width ${rendered.width}px exceeds the ${ARTICLE_WIDTH_HARD_LIMIT}px hard limit`,
    );
    for (const zone of THREAT_MODEL_ZONES) {
      assert.equal(rendered.frames.get(zone.id)?.tone, zone.tone);
      // Meaning never rides on color alone: the badge spells out the
      // tone and the zone label.
      const text = rendered.badges.get(zone.id)?.text ?? '';
      assert.ok(text.includes(ZONE_TONE_STYLE[zone.tone].label), `badge ${zone.id} lacks its tone: "${text}"`);
      assert.ok(text.includes(zone.label.replace('&', '&amp;')), `badge ${zone.id} lacks its label: "${text}"`);
    }
  });

  it('gives every badge room for its full text', () => {
    const { badges } = render(threatModel('nested'));
    for (const zone of THREAT_MODEL_ZONES) {
      // Mirrors measureZoneBadge in flow.tsx: the badge is never
      // squeezed below its own estimate.
      const estimate = Math.ceil(14 + ZONE_TONE_STYLE[zone.tone].label.length * 6 + 6 + zone.label.length * 5.6);
      assert.ok((badges.get(zone.id)?.width ?? 0) >= estimate, `badge ${zone.id} was clamped`);
    }
  });

  it('treats zone="id" on a Node the same as nesting it', () => {
    assert.equal(normalizeIds(render(threatModel('prop')).html), normalizeIds(render(threatModel('nested')).html));
  });

  it('renders a flow with only empty zones exactly like a flow with none', () => {
    const plain = (extra?: ReactNode) => (
      <Flow direction="TB">
        {extra}
        <Node id="a" kind="agent">Agent</Node>
        <Node id="b" kind="gateway">Gateway</Node>
        <Node id="c" kind="policy">Policy</Node>
        <Edge from="a" to="b" label="hook" />
        <Edge from="b" to="c" />
      </Flow>
    );
    const { result: withEmptyZone, warnings } = withWarningsCaptured(() =>
      render(plain(<Zone id="unused" label="Unused" tone="trusted" />)),
    );
    const without = render(plain());
    assert.equal(normalizeIds(withEmptyZone.html), normalizeIds(without.html));
    assert.doesNotMatch(without.html, /fd-flow-zone/);
    assert.ok(warnings.some((w) => w.includes('has no nodes')));
  });

  it('falls back to the external tone and warns on an unknown tone', () => {
    const { result, warnings } = withWarningsCaptured(() =>
      render(
        <Flow direction="TB">
          <Zone id="z" label="Mystery" tone={'friendly' as ZoneTone}>
            <Node id="a">A</Node>
          </Zone>
        </Flow>,
      ),
    );
    assert.equal(result.frames.get('z')?.tone, 'external');
    assert.ok(warnings.some((w) => w.includes('unknown tone')));
  });

  it('holds its geometry across seeded random graphs', () => {
    const tones = Object.keys(ZONE_TONE_STYLE) as ZoneTone[];
    const kinds: DiagramKind[] = ['agent', 'connector', 'gateway', 'policy', 'datastore', 'operator', 'generic'];
    for (let seed = 1; seed <= 300; seed++) {
      let state = seed;
      const random = () => {
        state = (state * 1664525 + 1013904223) >>> 0;
        return state / 2 ** 32;
      };
      const pick = <T,>(items: readonly T[]) => items[Math.floor(random() * items.length)];
      const nodeCount = 2 + Math.floor(random() * 12);
      const zoneCount = 1 + Math.floor(random() * Math.min(6, nodeCount));
      const zoneOf = Array.from({ length: nodeCount }, () =>
        random() < 0.85 ? `z${Math.floor(random() * zoneCount)}` : undefined,
      );
      const children: ReactNode[] = [];
      for (let z = 0; z < zoneCount; z++) {
        const label = `Z${z} · ${'Zone name '.repeat(1 + Math.floor(random() * 3)).trim()}`;
        children.push(<Zone key={`z${z}`} id={`z${z}`} label={label} tone={tones[z % tones.length]} />);
      }
      zoneOf.forEach((zone, i) => {
        children.push(
          <Node key={`n${i}`} id={`n${i}`} kind={pick(kinds)} zone={zone}>
            {random() < 0.3 ? `Node ${i}\nwith a detail line` : `Node ${i}`}
          </Node>,
        );
      });
      const edgeCount = Math.floor(random() * nodeCount * 1.6);
      for (let e = 0; e < edgeCount; e++) {
        // Includes cycles and the occasional self-loop.
        const from = Math.floor(random() * nodeCount);
        const to = Math.floor(random() * nodeCount);
        children.push(
          <Edge key={`e${e}`} from={`n${from}`} to={`n${to}`} label={random() < 0.5 ? `edge ${e}` : undefined} />,
        );
      }
      const direction = random() < 0.8 ? 'TB' : 'LR';
      const compact = random() < 0.2 ? false : undefined;
      const { result: rendered } = withWarningsCaptured(() =>
        render(
          <Flow direction={direction} compact={compact}>
            {children}
          </Flow>,
        ),
      );
      assert.deepEqual(zoneProblems(rendered, zoneOf), [], `seed ${seed} (${direction})`);
    }
  });
});
