// A standalone, GitHub-compatible git forge: REST v3, git smart HTTP (upload-pack v2,
// receive-pack v0), GraphQL v4 and MCP over streamable HTTP. Node standard library only,
// in-memory store, no git binary, no network beyond the trial's env.
//
// Determinism: no wall clock and no unseeded randomness reach any response. All timestamps
// derive from a fixed epoch plus a per-store counter, so a live pass and its replay answer
// identically. The token owner's login is derived from the kit's fixed scenario seed (the
// same pure generator the suite uses), never from a request.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------------------------
// The scenario identity: the token owner's login, from the kit's fixed scenario seed.
// (wire.ts's SCENARIO_SEED, fnv1a64, mix64, Rng and generateUsers, reimplemented pure.)
// ---------------------------------------------------------------------------------------------

const SCENARIO_SEED = 0x6a09e667f3bcc909n;
const U64_MASK = 0xffffffffffffffffn;

function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}

function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}

class ScenarioRng {
  #state: bigint;
  constructor(seed: bigint) {
    const masked = seed & U64_MASK;
    this.#state = masked === 0n ? SCENARIO_SEED : masked;
  }
  nextU64(): bigint {
    let x = this.#state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.#state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32(): number {
    return Number(this.nextU64() >> 32n);
  }
  nextInt(maxExclusive: number): number {
    if (maxExclusive === 1) return 0;
    const range = 4_294_967_296;
    const limit = range - (range % maxExclusive);
    for (;;) {
      const value = this.nextU32();
      if (value < limit) return value % maxExclusive;
    }
  }
  pick<T>(items: readonly T[]): T {
    return items[this.nextInt(items.length)] as T;
  }
}

const FIRST_NAMES: readonly string[] = [
  'ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars',
  'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane',
];
const LAST_NAMES: readonly string[] = [
  'anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller',
  'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber',
  'xu', 'yilmaz', 'zimmer',
];

function scenarioViewerLogin(): string {
  const rng = new ScenarioRng(mix64(SCENARIO_SEED ^ fnv1a64('users')));
  const used = new Set<string>();
  let firstLogin = '';
  for (let i = 0; i < 12; i += 1) {
    const first = rng.pick(FIRST_NAMES);
    const last = rng.pick(LAST_NAMES);
    const base = `${first}${last}`.replace(/[^a-z0-9-]/g, '');
    let login = base;
    let suffix = 2;
    while (used.has(login)) {
      login = `${base}-${suffix}`;
      suffix += 1;
    }
    used.add(login);
    if (i === 0) firstLogin = login;
  }
  return firstLogin;
}

/** The login the bearer token names. */
const VIEWER_LOGIN = scenarioViewerLogin();
/** The viewer's display name and email, as the scenario builds them. */
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';

// ---------------------------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------------------------

const ZERO_OID = '0'.repeat(40);
const JSON_TYPE = 'application/json; charset=utf-8';
/** Fixed epoch for every timestamp this server emits (2025-01-01T00:00:00Z). */
const EPOCH_MS = 1_735_689_600_000;

function sha1Hex(data: Buffer | Uint8Array): string {
  return createHash('sha1').update(data).digest('hex');
}

function b64encode(data: Buffer | string): string {
  return Buffer.isBuffer(data) ? data.toString('base64') : Buffer.from(data, 'utf8').toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

/** A stable ISO timestamp: the fixed epoch plus `seq` seconds (never the wall clock). */
function isoAt(seq: number): string {
  return new Date(EPOCH_MS + seq * 1000).toISOString();
}

/** Escape a string for safe inclusion in a JSON error message (no control characters). */
function safeText(value: unknown, max = 200): string {
  const text = typeof value === 'string' ? value : String(value ?? '');
  return text.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max);
}

// ---------------------------------------------------------------------------------------------
// pkt-line codec (git smart HTTP framing)
// ---------------------------------------------------------------------------------------------

const PKT_LINE_MAX = 65520;

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  if (data.length + 4 > PKT_LINE_MAX) throw new Error('pkt-line too long');
  const header = Buffer.allocUnsafe(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}

function pktFlush(): Buffer {
  return Buffer.from('0000', 'ascii');
}

function pktDelim(): Buffer {
  return Buffer.from('0001', 'ascii');
}

function pktResponseEnd(): Buffer {
  return Buffer.from('0002', 'ascii');
}

type Pkt =
  | { kind: 'data'; payload: Buffer }
  | { kind: 'flush' }
  | { kind: 'delim' }
  | { kind: 'response-end' };

/** Decode a whole buffer of pkt-lines. Throws on a malformed header. */
function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let offset = 0;
  while (offset < buf.length) {
    if (offset + 4 > buf.length) throw new Error('truncated pkt-line header');
    const head = buf.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error(`invalid pkt-line length ${JSON.stringify(head)}`);
    const len = Number.parseInt(head, 16);
    if (len === 0) {
      out.push({ kind: 'flush' });
      offset += 4;
    } else if (len === 1) {
      out.push({ kind: 'delim' });
      offset += 4;
    } else if (len === 2) {
      out.push({ kind: 'response-end' });
      offset += 4;
    } else {
      if (len < 4 || len > PKT_LINE_MAX) throw new Error(`invalid pkt-line length ${len}`);
      if (offset + len > buf.length) throw new Error('truncated pkt-line');
      out.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + len) });
      offset += len;
    }
  }
  return out;
}

/** The data-packet texts of a pkt-line stream, control packets dropped. */
function pktTexts(packets: readonly Pkt[]): string[] {
  const lines: string[] = [];
  for (const p of packets) if (p.kind === 'data') lines.push(p.payload.toString('utf8'));
  return lines;
}

// ---------------------------------------------------------------------------------------------
// Git object model
// ---------------------------------------------------------------------------------------------

type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObject {
  type: GitObjectType;
  data: Buffer;
}

const TYPE_CODE: Readonly<Record<GitObjectType, number>> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Readonly<Record<number, GitObjectType>> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: GitObjectType, data: Buffer): string {
  const hash = createHash('sha1');
  hash.update(Buffer.from(`${type} ${data.length}\0`, 'utf8'));
  hash.update(data);
  return hash.digest('hex');
}

function isOid(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) throw new Error('tree entry has no mode separator');
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0 || nul + 21 > data.length) throw new Error('tree entry truncated');
    entries.push({
      mode: data.subarray(offset, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: TreeEntry, b: TreeEntry): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    const key = space < 0 ? line : line.slice(0, space);
    const value = space < 0 ? '' : line.slice(space + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(tree: string, parents: readonly string[], message: string, who: string): Buffer {
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

interface TagView {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const headers = new Map<string, string>();
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    if (space >= 0) headers.set(line.slice(0, space), line.slice(space + 1));
  }
  return {
    object: headers.get('object') ?? '',
    type: headers.get('type') ?? '',
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8'),
  };
}

/** Every object reachable from `roots` (commits, trees, tags; gitlinks skipped). */
function collectReachable(roots: Iterable<string>, lookup: (oid: string) => GitObject | undefined): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const root of roots) if (isOid(root)) queue.push(root);
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const object = lookup(oid);
    if (!object) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      for (const parent of commit.parents) queue.push(parent);
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  return seen;
}

// ---------------------------------------------------------------------------------------------
// Packfile read/write
// ---------------------------------------------------------------------------------------------

function readVarintSize(buffer: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buffer[start] as number;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let offset = start + 1;
  while (byte & 0x80) {
    byte = buffer[offset++] as number;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, next: offset, first };
}

function readOfsDeltaBase(buffer: Buffer, start: number): { baseOffset: number; next: number } {
  let byte = buffer[start] as number;
  let offset = start + 1;
  let value = byte & 0x7f;
  while (byte & 0x80) {
    byte = buffer[offset++] as number;
    value = (value + 1) * 128 + (byte & 0x7f);
  }
  return { baseOffset: value, next: offset };
}

function inflateAt(buffer: Buffer, offset: number): { data: Buffer; next: number } {
  const result = inflateSync(buffer.subarray(offset), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  return { data: result.buffer, next: offset + result.engine.bytesWritten };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset++] as number;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset++] as number;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) copyOffset += (delta[offset++] as number) * 2 ** shift;
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) copySize += (delta[offset++] as number) * 2 ** shift;
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      delta.copy(out, written, offset, offset + literal);
      offset += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

interface PackReadResult {
  objects: Map<string, GitObject>;
  deltaCount: number;
}

/** Read a packfile (v2/v3), resolving OFS_DELTA and REF_DELTA. Throws on corruption. */
function readPack(pack: Buffer, resolveBase?: (oid: string) => GitObject | undefined): PackReadResult {
  if (pack.length < 32) throw new Error('pack too short');
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack header');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`pack version ${version}`);
  const declaredCount = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  if (sha1Hex(pack.subarray(0, trailerStart)) !== trailer) throw new Error('pack checksum');

  interface RawEntry {
    offset: number;
    typeCode: number;
    size: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
    resolvedType?: GitObjectType;
    resolved?: Buffer;
    oid?: string;
  }
  const raw: RawEntry[] = [];
  const byOffset = new Map<number, RawEntry>();
  let offset = 12;
  for (let index = 0; index < declaredCount; index += 1) {
    const entryOffset = offset;
    const header = readVarintSize(pack, offset);
    offset = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: RawEntry = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      const base = readOfsDeltaBase(pack, offset);
      offset = base.next;
      entry.baseOffset = entryOffset - base.baseOffset;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error(`pack entry unknown type ${typeCode}`);
    }
    const inflated = inflateAt(pack.subarray(0, trailerStart), offset);
    if (inflated.data.length !== header.size) throw new Error('pack entry size mismatch');
    entry.data = inflated.data;
    offset = inflated.next;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  if (offset !== trailerStart) throw new Error('pack trailing bytes');

  const objects = new Map<string, GitObject>();
  const resolvedByOid = new Map<string, RawEntry>();
  const resolving = new Set<number>();
  let deltaCount = 0;
  const resolve = (entry: RawEntry): { type: GitObjectType; data: Buffer; oid: string } => {
    if (entry.resolved && entry.resolvedType && entry.oid) return { type: entry.resolvedType, data: entry.resolved, oid: entry.oid };
    if (resolving.has(entry.offset)) throw new Error('delta cycle');
    resolving.add(entry.offset);
    let type: GitObjectType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset as number);
      if (!baseEntry) throw new Error('ofs-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const wanted = entry.baseOid as string;
      const baseEntry = resolvedByOid.get(wanted);
      if (baseEntry) {
        const base = resolve(baseEntry);
        type = base.type;
        data = applyDelta(base.data, entry.data);
      } else {
        const external = resolveBase?.(wanted);
        if (!external) throw new Error(`ref-delta base ${wanted} missing`);
        type = external.type;
        data = applyDelta(external.data, entry.data);
      }
    } else {
      type = CODE_TYPE[entry.typeCode] as GitObjectType;
      data = entry.data;
    }
    const oid = hashObject(type, data);
    entry.resolved = data;
    entry.resolvedType = type;
    entry.oid = oid;
    resolvedByOid.set(oid, entry);
    resolving.delete(entry.offset);
    return { type, data, oid };
  };
  for (const entry of raw) {
    const resolved = resolve(entry);
    if (entry.typeCode === 6 || entry.typeCode === 7) deltaCount += 1;
    if (!objects.has(resolved.oid)) objects.set(resolved.oid, { type: resolved.type, data: resolved.data });
  }
  return { objects, deltaCount };
}

function writePackObjectHeader(type: GitObjectType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile from plain objects (no deltas). */
function writePack(objects: Iterable<GitObject>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const object of list) {
    parts.push(writePackObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

// ---------------------------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------------------------

interface Label {
  name: string;
  color: string;
  description: string;
}

interface Comment {
  id: number;
  body: string;
  user: string;
  createdSeq: number;
}

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  comments: Comment[];
  createdSeq: number;
  updatedSeq: number;
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  createdSeq: number;
  updatedSeq: number;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  private: boolean;
  defaultBranch: string;
  createdSeq: number;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  /** commit oid -> creation sequence (ordering for GET /commits). */
  commitSeq: Map<string, number>;
  labels: Map<string, Label>;
  issues: Issue[];
  pulls: Pull[];
  /** O(1) lookup by shared issue/PR number. */
  issuesByNumber: Map<number, Issue>;
  pullsByNumber: Map<number, Pull>;
  /** Shared issue+PR numbering, GitHub-style. */
  nextNumber: number;
  /** Monotonic per-repo clock for file commits. */
  clock: number;
}

class Store {
  repos = new Map<string, Repo>();
  nextRepoId = 1;
  nextGlobalId = 1;
  seq = 1;
  /** Cache of built fetch packs, keyed by the fetch request. Bounded. */
  packCache = new Map<string, { pack: Buffer; shallow: string[]; unshallow: string[] }>();

  nextSeq(): number {
    return this.seq++;
  }

  createRepo(name: string, description: string, isPrivate: boolean): Repo {
    const repo: Repo = {
      id: this.nextRepoId++,
      name,
      owner: VIEWER_LOGIN,
      description,
      private: isPrivate,
      defaultBranch: 'main',
      createdSeq: this.nextSeq(),
      refs: new Map(),
      objects: new Map(),
      commitSeq: new Map(),
      labels: new Map(),
      issues: [],
      pulls: [],
      issuesByNumber: new Map(),
      pullsByNumber: new Map(),
      nextNumber: 1,
      clock: 0,
    };
    this.repos.set(name, repo);
    return repo;
  }

  getRepo(name: string): Repo | undefined {
    return this.repos.get(name);
  }

  deleteRepo(name: string): boolean {
    return this.repos.delete(name);
  }

  listRepos(): Repo[] {
    return [...this.repos.values()].sort((a, b) => a.createdSeq - b.createdSeq);
  }

  /** A global id, opaque and stable: base64 of `Type:internal`. */
  globalId(kind: string, internal: number | string): string {
    return b64encode(`${kind}:${internal}`);
  }

  decodeGlobalId(id: string): { kind: string; internal: string } | null {
    try {
      const text = b64decode(id).toString('utf8');
      const at = text.indexOf(':');
      if (at <= 0) return null;
      return { kind: text.slice(0, at), internal: text.slice(at + 1) };
    } catch {
      return null;
    }
  }

  /** The commit identity line this server signs its own commits with. */
  identityLine(seq: number): string {
    return `${VIEWER_NAME} <${VIEWER_EMAIL}> ${1_735_689_600 + seq} +0000`;
  }
}

const store = new Store();

// ---------------------------------------------------------------------------------------------
// Repo tree/commit helpers
// ---------------------------------------------------------------------------------------------

/** The tree oid at `path`'s parent, walking down from `rootTreeOid`; null when missing. */
function treeAtPath(repo: Repo, rootTreeOid: string, segments: readonly string[]): string | null {
  let current = rootTreeOid;
  for (const segment of segments) {
    const object = repo.objects.get(current);
    if (!object || object.type !== 'tree') return null;
    const entry = parseTree(object.data).find((e) => e.name === segment && e.mode === '40000');
    if (!entry) return null;
    current = entry.oid;
  }
  return current;
}

/** Look up a blob oid for a full path in a tree; null when absent. */
function blobAtPath(repo: Repo, rootTreeOid: string, path: string): { oid: string; mode: string } | null {
  const segments = path.split('/').filter((s) => s !== '');
  if (segments.length === 0) return null;
  const parent = segments.length === 1 ? rootTreeOid : treeAtPath(repo, rootTreeOid, segments.slice(0, -1));
  if (parent === null) return null;
  const object = repo.objects.get(parent);
  if (!object || object.type !== 'tree') return null;
  const entry = parseTree(object.data).find((e) => e.name === segments[segments.length - 1]);
  if (!entry || entry.mode === '40000') return null;
  return { oid: entry.oid, mode: entry.mode };
}

/** A new root tree with `path` set to `blobOid` (or removed when null). Stores new trees. */
function setPathInTree(repo: Repo, rootTreeOid: string | null, path: string, blobOid: string | null): string {
  const segments = path.split('/').filter((s) => s !== '');
  const build = (treeOid: string | null, depth: number): string => {
    const entries = new Map<string, TreeEntry>();
    if (treeOid !== null) {
      const object = repo.objects.get(treeOid);
      if (object && object.type === 'tree') {
        for (const entry of parseTree(object.data)) entries.set(entry.name, entry);
      }
    }
    const name = segments[depth] as string;
    if (depth === segments.length - 1) {
      if (blobOid === null) entries.delete(name);
      else entries.set(name, { mode: '100644', name, oid: blobOid });
    } else {
      const child = entries.get(name);
      const childTree = build(child && child.mode === '40000' ? child.oid : null, depth + 1);
      const childObject = repo.objects.get(childTree);
      const childEntries = childObject ? parseTree(childObject.data) : [];
      if (childEntries.length === 0) entries.delete(name);
      else entries.set(name, { mode: '40000', name, oid: childTree });
    }
    const data = buildTree([...entries.values()]);
    const oid = hashObject('tree', data);
    if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'tree', data });
    return oid;
  };
  return build(rootTreeOid, 0);
}

/** The flat path -> blob oid map of a tree (recursive). */
function flattenTree(repo: Repo, treeOid: string, prefix: string, out: Map<string, string>): void {
  const object = repo.objects.get(treeOid);
  if (!object || object.type !== 'tree') return;
  for (const entry of parseTree(object.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(repo, entry.oid, path, out);
    else if (entry.mode !== '160000') out.set(path, entry.oid);
  }
}

/** Store a blob's bytes; returns its oid. */
function putBlob(repo: Repo, data: Buffer): string {
  const oid = hashObject('blob', data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'blob', data });
  return oid;
}

/** Create a commit object on `repo` and store it; returns its oid. */
function putCommit(repo: Repo, treeOid: string, parents: readonly string[], message: string): string {
  repo.clock += 1;
  const who = store.identityLine(repo.clock);
  const data = buildCommit(treeOid, parents, message.endsWith('\n') ? message : `${message}\n`, who);
  const oid = hashObject('commit', data);
  if (!repo.objects.has(oid)) {
    repo.objects.set(oid, { type: 'commit', data });
    repo.commitSeq.set(oid, store.nextSeq());
  }
  return oid;
}

/** Resolve a ref name, branch name or oid to a commit oid; null when unresolvable. */
function resolveRef(repo: Repo, ref: string): string | null {
  if (isOid(ref)) return repo.objects.has(ref) ? ref : null;
  if (repo.refs.has(ref)) return repo.refs.get(ref) as string;
  if (repo.refs.has(`refs/heads/${ref}`)) return repo.refs.get(`refs/heads/${ref}`) as string;
  if (repo.refs.has(`refs/tags/${ref}`)) return repo.refs.get(`refs/tags/${ref}`) as string;
  return null;
}

/** The merge-base of two commits (nearest common ancestor by commit sequence). */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancestorsA = new Set<string>();
  const queueA = [a];
  while (queueA.length > 0) {
    const oid = queueA.pop() as string;
    if (ancestorsA.has(oid)) continue;
    ancestorsA.add(oid);
    const object = repo.objects.get(oid);
    if (object?.type === 'commit') queueA.push(...parseCommit(object.data).parents);
  }
  let best: string | null = null;
  let bestSeq = -1;
  const queueB = [b];
  const seenB = new Set<string>();
  while (queueB.length > 0) {
    const oid = queueB.pop() as string;
    if (seenB.has(oid)) continue;
    seenB.add(oid);
    if (ancestorsA.has(oid)) {
      const seq = repo.commitSeq.get(oid) ?? 0;
      if (seq > bestSeq) {
        bestSeq = seq;
        best = oid;
      }
    }
    const object = repo.objects.get(oid);
    if (object?.type === 'commit') queueB.push(...parseCommit(object.data).parents);
  }
  return best;
}

/** True when `ancestor` is reachable from `tip` (or equal). */
function isAncestor(repo: Repo, ancestor: string, tip: string): boolean {
  if (ancestor === tip) return true;
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (object?.type === 'commit') {
      for (const parent of parseCommit(object.data).parents) {
        if (parent === ancestor) return true;
        queue.push(parent);
      }
    } else if (object?.type === 'tag') {
      queue.push(parseTag(object.data).object);
    }
  }
  return false;
}

/** Peel a tag object to its commit (or the oid itself when not a tag). */
function peelToCommit(repo: Repo, oid: string): string {
  let current = oid;
  for (let i = 0; i < 8; i += 1) {
    const object = repo.objects.get(current);
    if (!object || object.type !== 'tag') return current;
    current = parseTag(object.data).object;
  }
  return current;
}

interface FileDiff {
  filename: string;
  status: 'added' | 'removed' | 'modified';
  additions: number;
  deletions: number;
}

/** Line counts for a small diff: multiset difference of lines. */
function lineDiffCounts(oldText: string, newText: string): { additions: number; deletions: number } {
  const countLines = (text: string): Map<string, number> => {
    const map = new Map<string, number>();
    for (const line of text.split('\n')) map.set(line, (map.get(line) ?? 0) + 1);
    return map;
  };
  const oldLines = countLines(oldText);
  const newLines = countLines(newText);
  let additions = 0;
  let deletions = 0;
  for (const [line, count] of newLines) {
    const old = oldLines.get(line) ?? 0;
    if (count > old) additions += count - old;
  }
  for (const [line, count] of oldLines) {
    const next = newLines.get(line) ?? 0;
    if (count > next) deletions += count - next;
  }
  return { additions, deletions };
}

/** The file-level diff between two trees (base -> head). */
function diffTrees(repo: Repo, baseTreeOid: string | null, headTreeOid: string | null): FileDiff[] {
  const base = new Map<string, string>();
  const head = new Map<string, string>();
  if (baseTreeOid) flattenTree(repo, baseTreeOid, '', base);
  if (headTreeOid) flattenTree(repo, headTreeOid, '', head);
  const out: FileDiff[] = [];
  const paths = new Set([...base.keys(), ...head.keys()]);
  for (const path of [...paths].sort()) {
    const b = base.get(path);
    const h = head.get(path);
    if (b === h) continue;
    if (b === undefined) {
      const data = repo.objects.get(h as string)?.data ?? Buffer.alloc(0);
      const counts = lineDiffCounts('', data.toString('utf8'));
      out.push({ filename: path, status: 'added', additions: counts.additions, deletions: 0 });
    } else if (h === undefined) {
      const data = repo.objects.get(b)?.data ?? Buffer.alloc(0);
      const counts = lineDiffCounts(data.toString('utf8'), '');
      out.push({ filename: path, status: 'removed', additions: 0, deletions: counts.deletions });
    } else {
      const oldData = repo.objects.get(b)?.data ?? Buffer.alloc(0);
      const newData = repo.objects.get(h)?.data ?? Buffer.alloc(0);
      const counts = lineDiffCounts(oldData.toString('utf8'), newData.toString('utf8'));
      out.push({ filename: path, status: 'modified', additions: counts.additions, deletions: counts.deletions });
    }
  }
  return out;
}

/** Squash-merge `pull` onto its base branch. Returns the merge commit oid, or null on conflict. */
function squashMerge(repo: Repo, pull: Pull): string | null {
  const baseTip = resolveRef(repo, pull.baseRef);
  const headTip = resolveRef(repo, pull.headRef);
  if (baseTip === null || headTip === null) return null;
  const base = mergeBase(repo, baseTip, headTip);
  const baseTree = base === null ? null : parseCommit(repo.objects.get(base)?.data ?? Buffer.alloc(0)).tree;
  const headTree = parseCommit(repo.objects.get(headTip)?.data ?? Buffer.alloc(0)).tree;
  const baseTipTree = parseCommit(repo.objects.get(baseTip)?.data ?? Buffer.alloc(0)).tree;
  const headDiff = diffTrees(repo, baseTree, headTree);
  const baseDiff = diffTrees(repo, baseTree, baseTipTree);
  const baseChanged = new Map(baseDiff.map((d) => [d.filename, d]));
  // Conflict: both sides changed the same path, and the base side's result differs from the head's.
  const headFlat = new Map<string, string>();
  const baseTipFlat = new Map<string, string>();
  flattenTree(repo, headTree, '', headFlat);
  flattenTree(repo, baseTipTree, '', baseTipFlat);
  for (const change of headDiff) {
    if (baseChanged.has(change.filename)) {
      const headOid = headFlat.get(change.filename);
      const baseOid = baseTipFlat.get(change.filename);
      if (headOid !== baseOid) return null;
    }
  }
  // Apply the head's changes onto the base tip's tree.
  let tree = baseTipTree;
  const baseFlat = new Map<string, string>();
  flattenTree(repo, baseTipTree, '', baseFlat);
  for (const change of headDiff) {
    const oid = headFlat.get(change.filename) ?? null;
    tree = setPathInTree(repo, tree, change.filename, oid);
  }
  const message = `${pull.title} (#${pull.number})\n`;
  const mergeSha = putCommit(repo, tree, [baseTip], message);
  repo.refs.set(`refs/heads/${pull.baseRef}`, mergeSha);
  return mergeSha;
}

/** Whether a pull request can merge cleanly right now. */
function pullMergeable(repo: Repo, pull: Pull): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  if (pull.state !== 'open') return 'UNKNOWN';
  const baseTip = resolveRef(repo, pull.baseRef);
  const headTip = resolveRef(repo, pull.headRef);
  if (baseTip === null || headTip === null) return 'UNKNOWN';
  const base = mergeBase(repo, baseTip, headTip);
  const baseTree = base === null ? null : parseCommit(repo.objects.get(base)?.data ?? Buffer.alloc(0)).tree;
  const headTree = parseCommit(repo.objects.get(headTip)?.data ?? Buffer.alloc(0)).tree;
  const baseTipTree = parseCommit(repo.objects.get(baseTip)?.data ?? Buffer.alloc(0)).tree;
  const headDiff = diffTrees(repo, baseTree, headTree);
  const baseDiff = diffTrees(repo, baseTree, baseTipTree);
  const baseChanged = new Map(baseDiff.map((d) => [d.filename, d]));
  const headFlat = new Map<string, string>();
  const baseTipFlat = new Map<string, string>();
  flattenTree(repo, headTree, '', headFlat);
  flattenTree(repo, baseTipTree, '', baseTipFlat);
  for (const change of headDiff) {
    if (baseChanged.has(change.filename) && headFlat.get(change.filename) !== baseTipFlat.get(change.filename)) {
      return 'CONFLICTING';
    }
  }
  return 'MERGEABLE';
}

// ---------------------------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------------------------

const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
let requestCounter = 0;

function nextRequestId(): string {
  requestCounter += 1;
  return `req-${requestCounter.toString(36)}`;
}

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders: Record<string, string> = {}): void {
  const text = body === null ? '' : `${JSON.stringify(body)}\n`;
  const headers: Record<string, string> = {
    'x-github-request-id': nextRequestId(),
    ...extraHeaders,
  };
  if (body !== null) {
    const buf = Buffer.from(text, 'utf8');
    headers['content-type'] = JSON_TYPE;
    headers['content-length'] = String(buf.length);
    res.writeHead(status, headers);
    res.end(buf);
    return;
  }
  res.writeHead(status, headers);
  res.end(text);
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function readBody(req: IncomingMessage, maxBytes = 64 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  path: string;
  segments: string[];
  query: URLSearchParams;
  body: Buffer;
  json: Record<string, unknown> | null;
  authed: boolean;
}

function parseBodyJson(ctx: Ctx): boolean {
  if (ctx.body.length === 0) {
    ctx.json = null;
    return true;
  }
  try {
    const parsed: unknown = JSON.parse(ctx.body.toString('utf8'));
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      sendError(ctx.res, 400, 'Invalid JSON body: expected an object');
      return false;
    }
    ctx.json = parsed as Record<string, unknown>;
    return true;
  } catch {
    sendError(ctx.res, 400, 'Invalid JSON body');
    return false;
  }
}

function authed(req: IncomingMessage): boolean {
  if (TOKEN === '') return true;
  const header = req.headers.authorization ?? '';
  return header === `Bearer ${TOKEN}`;
}

function paginate<T>(items: readonly T[], query: URLSearchParams, basePath: string, host: string): { page: T[]; link: string | null } {
  const perPageRaw = Number.parseInt(query.get('per_page') ?? '', 10);
  const pageRaw = Number.parseInt(query.get('page') ?? '', 10);
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(perPageRaw, 100) : 30;
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? pageRaw : 1;
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  let link: string | null = null;
  if (start + perPage < items.length) {
    const next = new URL(`http://${host}${basePath}`);
    next.searchParams.set('per_page', String(perPage));
    next.searchParams.set('page', String(page + 1));
    link = `<${next.toString()}>; rel="next"`;
  }
  return { page: [...slice], link };
}

function linkHeader(link: string | null): Record<string, string> {
  return link === null ? {} : { link };
}

// ---------------------------------------------------------------------------------------------
// REST v3 shapes
// ---------------------------------------------------------------------------------------------

/** The viewer user object is identical in every response: build it once per login. */
const userJsonCache = new Map<string, Record<string, unknown>>();

function userJson(login: string): Record<string, unknown> {
  const cached = userJsonCache.get(login);
  if (cached) return cached;
  const built: Record<string, unknown> = {
    login,
    id: 1000,
    node_id: store.globalId('User', 1000),
    avatar_url: `https://avatars.example.invalid/${login}`,
    type: 'User',
    site_admin: false,
    name: VIEWER_NAME,
    email: VIEWER_EMAIL,
    html_url: `https://example.invalid/${login}`,
    url: `/api/v3/users/${login}`,
  };
  userJsonCache.set(login, built);
  return built;
}

function repoJson(repo: Repo): Record<string, unknown> {
  const seq = repo.createdSeq;
  return {
    id: repo.id,
    node_id: store.globalId('Repository', repo.id),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    private: repo.private,
    owner: userJson(repo.owner),
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    description: repo.description,
    fork: false,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    created_at: isoAt(seq),
    updated_at: isoAt(seq),
    pushed_at: isoAt(seq),
    git_url: `git://example.invalid/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@example.invalid:${repo.owner}/${repo.name}.git`,
    clone_url: `https://example.invalid/${repo.owner}/${repo.name}.git`,
    homepage: null,
    size: 0,
    stargazers_count: 0,
    watchers_count: 0,
    language: null,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    has_discussions: false,
    forks_count: 0,
    archived: false,
    disabled: false,
    open_issues_count: repo.issues.filter((i) => i.state === 'open').length,
    license: null,
    allow_forking: true,
    is_template: false,
    web_commit_signoff_required: false,
    topics: [],
    visibility: repo.private ? 'private' : 'public',
    forks: 0,
    open_issues: repo.issues.filter((i) => i.state === 'open').length,
    watchers: 0,
    default_branch: repo.defaultBranch,
  };
}

function labelJson(label: Label): Record<string, unknown> {
  return {
    id: store.nextGlobalId,
    node_id: store.globalId('Label', label.name),
    url: `/api/v3/labels/${encodeURIComponent(label.name)}`,
    name: label.name,
    color: label.color,
    description: label.description,
    default: false,
  };
}

function issueJson(issue: Issue, repo: Repo): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: store.globalId('Issue', issue.id),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    labels_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/labels{/name}`,
    comments_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/comments`,
    events_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/events`,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
    number: issue.number,
    state: issue.state,
    title: issue.title,
    body: issue.body,
    user: userJson(repo.owner),
    labels: issue.labels.map(labelJson),
    assignee: null,
    assignees: [],
    milestone: null,
    locked: false,
    active_lock_reason: null,
    comments: issue.comments.length,
    created_at: isoAt(issue.createdSeq),
    updated_at: isoAt(issue.updatedSeq),
    closed_at: issue.state === 'closed' ? isoAt(issue.updatedSeq) : null,
    author_association: 'OWNER',
    state_reason: null,
  };
}

function pullJson(pull: Pull, repo: Repo): Record<string, unknown> {
  const headSha = resolveRef(repo, pull.headRef) ?? pull.headSha;
  const baseSha = resolveRef(repo, pull.baseRef) ?? pull.baseSha;
  return {
    id: pull.id,
    node_id: store.globalId('PullRequest', pull.id),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`,
    diff_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pull.number}.diff`,
    patch_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pull.number}.patch`,
    issue_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${pull.number}`,
    number: pull.number,
    state: pull.state,
    locked: false,
    title: pull.title,
    body: pull.body,
    user: userJson(repo.owner),
    labels: [],
    milestone: null,
    active_lock_reason: null,
    created_at: isoAt(pull.createdSeq),
    updated_at: isoAt(pull.updatedSeq),
    closed_at: pull.state === 'closed' ? isoAt(pull.updatedSeq) : null,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    merged: pull.merged,
    mergeable: pull.state === 'open' ? pullMergeable(repo, pull) === 'MERGEABLE' : null,
    mergeable_state: pull.state === 'open' ? (pullMergeable(repo, pull) === 'MERGEABLE' ? 'clean' : 'dirty') : 'unknown',
    merged_by: pull.merged ? userJson(repo.owner) : null,
    comments: 0,
    review_comments: 0,
    commits: 1,
    additions: 0,
    deletions: 0,
    changed_files: 0,
    head: {
      label: `${repo.owner}:${pull.headRef}`,
      ref: pull.headRef,
      sha: headSha,
      user: userJson(repo.owner),
      repo: repoJson(repo),
    },
    base: {
      label: `${repo.owner}:${pull.baseRef}`,
      ref: pull.baseRef,
      sha: baseSha,
      user: userJson(repo.owner),
      repo: repoJson(repo),
    },
    author_association: 'OWNER',
    auto_merge: null,
    draft: false,
  };
}

function commentJson(comment: Comment, repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: store.globalId('IssueComment', comment.id),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/comments/${comment.id}`,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
    body: comment.body,
    user: userJson(repo.owner),
    created_at: isoAt(comment.createdSeq),
    updated_at: isoAt(comment.createdSeq),
    author_association: 'OWNER',
  };
}

/** Parse an author line `Name <email> ts +0000` into its parts. */
function parseWho(line: string): { name: string; email: string; date: string } {
  const match = /^(.*?) <(.*?)> (\d+) ([+-]\d{4})$/.exec(line);
  if (!match) return { name: line, email: '', date: isoAt(0) };
  return { name: match[1] ?? '', email: match[2] ?? '', date: new Date(Number(match[3]) * 1000).toISOString() };
}

function commitJson(repo: Repo, oid: string): Record<string, unknown> {
  const object = repo.objects.get(oid);
  const view = object && object.type === 'commit' ? parseCommit(object.data) : { tree: '', parents: [], author: '', committer: '', message: '' };
  const author = parseWho(view.author);
  const committer = parseWho(view.committer);
  // GitHub surfaces the commit message without the trailing newline the object carries.
  const message = view.message.replace(/\n$/, '');
  return {
    sha: oid,
    node_id: store.globalId('Commit', oid),
    commit: {
      author: { name: author.name, email: author.email, date: author.date },
      committer: { name: committer.name, email: committer.email, date: committer.date },
      message,
      tree: { sha: view.tree },
      url: `/api/v3/repos/${repo.owner}/${repo.name}/git/commits/${oid}`,
      comment_count: 0,
      verification: { verified: false, reason: 'unsigned', signature: null, payload: null },
    },
    url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${oid}`,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/commit/${oid}`,
    comments_url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${oid}/comments`,
    author: userJson(repo.owner),
    committer: userJson(repo.owner),
    parents: view.parents.map((p) => ({ sha: p, url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${p}`, html_url: `https://example.invalid/${repo.owner}/${repo.name}/commit/${p}` })),
  };
}

// ---------------------------------------------------------------------------------------------
// REST v3 handlers
// ---------------------------------------------------------------------------------------------

function repoFromPath(ctx: Ctx, ownerIndex: number, nameIndex: number): Repo | null {
  const owner = ctx.segments[ownerIndex];
  const name = ctx.segments[nameIndex];
  if (owner === undefined || name === undefined) return null;
  const repo = store.getRepo(decodeURIComponent(name));
  if (!repo || repo.owner !== decodeURIComponent(owner)) return null;
  return repo;
}

function handleRest(ctx: Ctx): boolean {
  const { req, res } = ctx;
  const method = req.method ?? 'GET';
  const seg = ctx.segments;
  // All /api/v3 routes require the bearer token.
  if (!ctx.authed) {
    sendError(res, 401, 'Requires authentication');
    return true;
  }
  const host = req.headers.host ?? 'localhost';

  // GET /api/v3/ — the API root.
  if (seg.length === 2 && method === 'GET') {
    sendJson(res, 200, {
      current_user_url: '/api/v3/user',
      current_user_authorizations_html_url: 'https://example.invalid/settings/applications',
      authorizations_url: '/api/v3/authorizations',
      code_search_url: '/api/v3/search/code?q={query}',
      commit_search_url: '/api/v3/search/commits?q={query}',
      emails_url: '/api/v3/user/emails',
      emojis_url: '/api/v3/emojis',
      events_url: '/api/v3/events',
      feeds_url: '/api/v3/feeds',
      following_url: '/api/v3/user/following{/target}',
      gists_url: '/api/v3/gists{/gist_id}',
      hub_url: 'https://example.invalid/hub',
      issue_search_url: '/api/v3/search/issues?q={query}',
      issues_url: '/api/v3/issues',
      keys_url: '/api/v3/user/keys',
      label_search_url: '/api/v3/search/labels?q={query}',
      notifications_url: '/api/v3/notifications',
      organization_repositories_url: '/api/v3/orgs/{org}/repos',
      organization_url: '/api/v3/orgs/{org}',
      public_gists_url: '/api/v3/gists/public',
      rate_limit_url: '/api/v3/rate_limit',
      repository_url: '/api/v3/repos/{owner}/{repo}',
      repository_search_url: '/api/v3/search/repositories?q={query}',
      current_user_repositories_url: '/api/v3/user/repos',
      starred_url: '/api/v3/user/starred{/owner}{/repo}',
      starred_gists_url: '/api/v3/gists/starred',
      topic_search_url: '/api/v3/search/topics?q={query}',
      user_url: '/api/v3/users/{user}',
      user_organizations_url: '/api/v3/user/orgs',
      user_repositories_url: '/api/v3/users/{user}/repos',
      user_search_url: '/api/v3/search/users?q={query}',
    }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }

  // GET /api/v3/meta
  if (seg.length === 3 && seg[2] === 'meta' && method === 'GET') {
    sendJson(res, 200, { verifiable_password_authentication: true, installed_version: '1.0.0' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }

  // GET /api/v3/user
  if (seg.length === 3 && seg[2] === 'user' && method === 'GET') {
    sendJson(res, 200, userJson(VIEWER_LOGIN), { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }

  // /api/v3/user/repos
  if (seg.length === 4 && seg[2] === 'user' && seg[3] === 'repos') {
    if (method === 'GET') {
      const { page, link } = paginate(store.listRepos().map(repoJson), ctx.query, '/api/v3/user/repos', host);
      sendJson(res, 200, page, { 'x-oauth-scopes': 'repo, read:org', ...linkHeader(link) });
      return true;
    }
    if (method === 'POST') {
      if (!parseBodyJson(ctx)) return true;
      const body = ctx.json as Record<string, unknown>;
      const name = typeof body.name === 'string' ? body.name.trim() : '';
      if (name === '' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name) || name.endsWith('.git')) {
        sendError(res, 422, 'Validation Failed: name is invalid');
        return true;
      }
      if (store.getRepo(name)) {
        sendError(res, 422, 'Repository already exists');
        return true;
      }
      const repo = store.createRepo(
        name,
        typeof body.description === 'string' ? body.description : '',
        body.private === true,
      );
      sendJson(res, 201, repoJson(repo), { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    return false;
  }

  // /api/v3/repos/{owner}/{repo}[...]
  if (seg.length >= 5 && seg[2] === 'repos') {
    return handleRepoRest(ctx);
  }

  return false;
}

function handleRepoRest(ctx: Ctx): boolean {
  const { req, res } = ctx;
  const method = req.method ?? 'GET';
  const seg = ctx.segments;
  const repo = repoFromPath(ctx, 3, 4);
  if (!repo) {
    sendError(res, 404, 'Not Found');
    return true;
  }
  const rest = seg.slice(5);
  const host = req.headers.host ?? 'localhost';

  // GET / PATCH / DELETE /api/v3/repos/{o}/{r}
  if (rest.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, repoJson(repo), { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    if (method === 'PATCH') {
      if (!parseBodyJson(ctx)) return true;
      const body = ctx.json as Record<string, unknown>;
      if (typeof body.description === 'string') repo.description = body.description;
      if (typeof body.private === 'boolean') repo.private = body.private;
      sendJson(res, 200, repoJson(repo), { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    if (method === 'DELETE') {
      store.deleteRepo(repo.name);
      sendJson(res, 204, null);
      return true;
    }
    return false;
  }

  const head = rest[0];

  // Branches
  if (head === 'branches') {
    if (rest.length === 1 && method === 'GET') {
      const list = [...repo.refs.keys()]
        .filter((r) => r.startsWith('refs/heads/'))
        .sort()
        .map((r) => ({
          name: r.slice('refs/heads/'.length),
          commit: { sha: repo.refs.get(r) as string, url: '' },
          protected: false,
        }));
      sendJson(res, 200, list, { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    if (rest.length === 2 && method === 'GET') {
      const branch = decodeURIComponent(rest[1] as string);
      const sha = repo.refs.get(`refs/heads/${branch}`);
      if (!sha) {
        sendError(res, 404, 'Not Found');
        return true;
      }
      sendJson(res, 200, { name: branch, commit: { sha, url: '' }, protected: false }, { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    return false;
  }

  // Commits
  if (head === 'commits' && method === 'GET') {
    const refParam = ctx.query.get('sha') ?? repo.defaultBranch;
    const tip = resolveRef(repo, refParam);
    if (tip === null) {
      sendJson(res, 200, [], { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    const seen = new Set<string>();
    const queue = [tip];
    const found: string[] = [];
    while (queue.length > 0) {
      const oid = queue.pop() as string;
      if (seen.has(oid)) continue;
      seen.add(oid);
      const object = repo.objects.get(oid);
      if (!object || object.type !== 'commit') continue;
      found.push(oid);
      queue.push(...parseCommit(object.data).parents);
    }
    found.sort((a, b) => (repo.commitSeq.get(b) ?? 0) - (repo.commitSeq.get(a) ?? 0));
    const { page, link } = paginate(found.map((oid) => commitJson(repo, oid)), ctx.query, ctx.path, host);
    sendJson(res, 200, page, { 'x-oauth-scopes': 'repo, read:org', ...linkHeader(link) });
    return true;
  }

  // Git refs
  if (head === 'git' && rest[1] === 'refs') {
    if (method === 'POST' && rest.length === 2) {
      if (!parseBodyJson(ctx)) return true;
      const body = ctx.json as Record<string, unknown>;
      const ref = typeof body.ref === 'string' ? body.ref : '';
      const sha = typeof body.sha === 'string' ? body.sha : '';
      if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) {
        sendError(res, 422, 'Validation Failed: ref or sha is invalid');
        return true;
      }
      if (repo.refs.has(ref)) {
        sendError(res, 422, 'Reference already exists');
        return true;
      }
      repo.refs.set(ref, sha);
      sendJson(res, 201, { ref, node_id: store.globalId('Ref', ref), url: '', object: { sha, type: 'commit', url: '' } }, { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    if (method === 'GET' && rest.length >= 3) {
      const ref = rest.slice(2).map(decodeURIComponent).join('/');
      const sha = repo.refs.get(ref);
      if (!sha) {
        sendError(res, 404, 'Not Found');
        return true;
      }
      const object = repo.objects.get(sha);
      sendJson(res, 200, { ref, node_id: store.globalId('Ref', ref), url: '', object: { sha, type: object?.type ?? 'commit', url: '' } }, { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    return false;
  }

  // Contents
  if (head === 'contents') {
    return handleContents(ctx, repo, rest.slice(1));
  }

  // Labels
  if (head === 'labels') {
    if (method === 'GET' && rest.length === 1) {
      sendJson(res, 200, [...repo.labels.values()].map(labelJson), { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    if (method === 'POST' && rest.length === 1) {
      if (!parseBodyJson(ctx)) return true;
      const body = ctx.json as Record<string, unknown>;
      const name = typeof body.name === 'string' ? body.name.trim() : '';
      if (name === '') {
        sendError(res, 422, 'Validation Failed: name is required');
        return true;
      }
      const existing = repo.labels.get(name);
      if (existing) {
        sendJson(res, 200, labelJson(existing), { 'x-oauth-scopes': 'repo, read:org' });
        return true;
      }
      const label: Label = {
        name,
        color: typeof body.color === 'string' ? body.color.replace(/^#/, '') : 'ededed',
        description: typeof body.description === 'string' ? body.description : '',
      };
      repo.labels.set(name, label);
      sendJson(res, 201, labelJson(label), { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    return false;
  }

  // Issues
  if (head === 'issues') {
    return handleIssues(ctx, repo, rest.slice(1));
  }

  // Pulls
  if (head === 'pulls') {
    return handlePulls(ctx, repo, rest.slice(1));
  }

  return false;
}

/** Resolve the tip commit for a contents read/write: branch name, ref or oid. */
function contentsTip(repo: Repo, refParam: string | null): { commit: string; branch: string } | null {
  if (refParam === null || refParam === '') {
    const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
    return tip === undefined ? null : { commit: tip, branch: repo.defaultBranch };
  }
  const tip = resolveRef(repo, refParam);
  if (tip === null) return null;
  return { commit: tip, branch: refParam };
}

function handleContents(ctx: Ctx, repo: Repo, pathSegments: readonly string[]): boolean {
  const { req, res } = ctx;
  const method = req.method ?? 'GET';
  const path = pathSegments.map(decodeURIComponent).join('/');
  const refParam = ctx.query.get('ref');

  if (method === 'GET') {
    const tip = contentsTip(repo, refParam);
    if (tip === null) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const commitObject = repo.objects.get(tip.commit);
    if (!commitObject || commitObject.type !== 'commit') {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const rootTree = parseCommit(commitObject.data).tree;
    if (path === '') {
      const entries = dirListing(repo, rootTree, '');
      sendJson(res, 200, entries, { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    const blob = blobAtPath(repo, rootTree, path);
    if (blob !== null) {
      const data = repo.objects.get(blob.oid)?.data ?? Buffer.alloc(0);
      sendJson(res, 200, {
        type: 'file',
        encoding: 'base64',
        size: data.length,
        name: path.split('/').pop() ?? path,
        path,
        content: b64encode(data),
        sha: blob.oid,
        url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${path}`,
        html_url: `https://example.invalid/${repo.owner}/${repo.name}/blob/${tip.branch}/${path}`,
        git_url: `/api/v3/repos/${repo.owner}/${repo.name}/git/blobs/${blob.oid}`,
        download_url: `https://example.invalid/${repo.owner}/${repo.name}/raw/${tip.branch}/${path}`,
        _links: {},
      }, { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    // A directory?
    const segments = path.split('/').filter((s) => s !== '');
    const dirTree = treeAtPath(repo, rootTree, segments);
    if (dirTree !== null) {
      sendJson(res, 200, dirListing(repo, dirTree, path), { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }

  if (method === 'PUT') {
    if (!parseBodyJson(ctx)) return true;
    const body = ctx.json as Record<string, unknown>;
    const message = typeof body.message === 'string' && body.message !== '' ? body.message : `Update ${path}`;
    const contentB64 = typeof body.content === 'string' ? body.content : '';
    if (contentB64 === '') {
      sendError(res, 422, 'Validation Failed: content is required');
      return true;
    }
    const data = b64decode(contentB64);
    const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
    let tip = repo.refs.get(`refs/heads/${branch}`);
    let baseCommit: string | null = null;
    let baseTree: string | null = null;
    if (tip !== undefined) {
      const commitObject = repo.objects.get(tip);
      if (commitObject?.type === 'commit') {
        baseCommit = tip;
        baseTree = parseCommit(commitObject.data).tree;
      }
    } else if (branch !== repo.defaultBranch) {
      // Create the branch from the default branch tip (the MCP fallback path).
      const defaultTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      if (defaultTip !== undefined) {
        const commitObject = repo.objects.get(defaultTip);
        if (commitObject?.type === 'commit') {
          baseCommit = defaultTip;
          baseTree = parseCommit(commitObject.data).tree;
        }
      }
    }
    const existing = baseTree === null ? null : blobAtPath(repo, baseTree, path);
    const sha = typeof body.sha === 'string' ? body.sha : undefined;
    if (existing !== null) {
      if (sha === undefined || sha.toLowerCase() !== existing.oid.toLowerCase()) {
        sendError(res, 409, 'Conflict: sha does not match the current blob');
        return true;
      }
    } else if (sha !== undefined) {
      sendError(res, 409, 'Conflict: sha does not match the current blob');
      return true;
    }
    const blobOid = putBlob(repo, data);
    const newTree = setPathInTree(repo, baseTree, path, blobOid);
    const parents = baseCommit === null ? [] : [baseCommit];
    const commitSha = putCommit(repo, newTree, parents, message);
    repo.refs.set(`refs/heads/${branch}`, commitSha);
    const status = existing !== null ? 200 : 201;
    sendJson(res, status, {
      content: {
        name: path.split('/').pop() ?? path,
        path,
        sha: blobOid,
        size: data.length,
        url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${path}`,
        html_url: `https://example.invalid/${repo.owner}/${repo.name}/blob/${branch}/${path}`,
        git_url: `/api/v3/repos/${repo.owner}/${repo.name}/git/blobs/${blobOid}`,
        download_url: `https://example.invalid/${repo.owner}/${repo.name}/raw/${branch}/${path}`,
        type: 'file',
        encoding: 'base64',
        content: b64encode(data),
        _links: {},
      },
      commit: commitJson(repo, commitSha),
    }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }

  if (method === 'DELETE') {
    if (!parseBodyJson(ctx)) return true;
    const body = ctx.json as Record<string, unknown>;
    const message = typeof body.message === 'string' && body.message !== '' ? body.message : `Delete ${path}`;
    const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
    const tip = repo.refs.get(`refs/heads/${branch}`);
    if (tip === undefined) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const commitObject = repo.objects.get(tip);
    if (!commitObject || commitObject.type !== 'commit') {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const baseTree = parseCommit(commitObject.data).tree;
    const existing = blobAtPath(repo, baseTree, path);
    if (existing === null) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const sha = typeof body.sha === 'string' ? body.sha : undefined;
    if (sha !== undefined && sha.toLowerCase() !== existing.oid.toLowerCase()) {
      sendError(res, 409, 'Conflict: sha does not match the current blob');
      return true;
    }
    const newTree = setPathInTree(repo, baseTree, path, null);
    const commitSha = putCommit(repo, newTree, [tip], message);
    repo.refs.set(`refs/heads/${branch}`, commitSha);
    sendJson(res, 200, { commit: commitJson(repo, commitSha) }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }

  return false;
}

function dirListing(repo: Repo, treeOid: string, prefix: string): Record<string, unknown>[] {
  const object = repo.objects.get(treeOid);
  if (!object || object.type !== 'tree') return [];
  return parseTree(object.data).map((entry) => {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    const isDir = entry.mode === '40000';
    const data = isDir ? null : repo.objects.get(entry.oid)?.data;
    return {
      type: isDir ? 'dir' : 'file',
      size: isDir ? 0 : (data?.length ?? 0),
      name: entry.name,
      path,
      sha: entry.oid,
      url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${path}`,
      html_url: `https://example.invalid/${repo.owner}/${repo.name}/tree/${repo.defaultBranch}/${path}`,
      git_url: `/api/v3/repos/${repo.owner}/${repo.name}/git/${isDir ? 'trees' : 'blobs'}/${entry.oid}`,
      download_url: isDir ? null : `https://example.invalid/${repo.owner}/${repo.name}/raw/${repo.defaultBranch}/${path}`,
      _links: {},
    };
  });
}

function handleIssues(ctx: Ctx, repo: Repo, rest: readonly string[]): boolean {
  const { req, res } = ctx;
  const method = req.method ?? 'GET';
  const host = req.headers.host ?? 'localhost';

  if (rest.length === 0) {
    if (method === 'GET') {
      const state = ctx.query.get('state') ?? 'open';
      const sort = ctx.query.get('sort') ?? 'created';
      const direction = ctx.query.get('direction') ?? 'desc';
      let list = [...repo.issues];
      if (state === 'open') list = list.filter((i) => i.state === 'open');
      else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
      if (sort === 'created') {
        list.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
      }
      const { page, link } = paginate(list.map((i) => issueJson(i, repo)), ctx.query, ctx.path, host);
      sendJson(res, 200, page, { 'x-oauth-scopes': 'repo, read:org', ...linkHeader(link) });
      return true;
    }
    if (method === 'POST') {
      if (!parseBodyJson(ctx)) return true;
      const body = ctx.json as Record<string, unknown>;
      const title = typeof body.title === 'string' ? body.title : '';
      if (title === '') {
        sendError(res, 422, 'Validation Failed: title is required');
        return true;
      }
      const labelsRaw = Array.isArray(body.labels) ? body.labels : [];
      const labels: Label[] = [];
      for (const raw of labelsRaw) {
        const name = typeof raw === 'string' ? raw : typeof raw === 'object' && raw !== null ? String((raw as Record<string, unknown>).name ?? '') : '';
        const found = repo.labels.get(name);
        if (!found) {
          sendError(res, 422, `Validation Failed: label "${name}" does not exist`);
          return true;
        }
        labels.push(found);
      }
      const seq = store.nextSeq();
      const issue: Issue = {
        id: store.nextGlobalId++,
        number: repo.nextNumber++,
        title,
        body: typeof body.body === 'string' ? body.body : '',
        state: 'open',
        labels,
        comments: [],
        createdSeq: seq,
        updatedSeq: seq,
      };
      repo.issues.push(issue);
      repo.issuesByNumber.set(issue.number, issue);
      sendJson(res, 201, issueJson(issue, repo), { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    return false;
  }

  const number = Number.parseInt(rest[0] ?? '', 10);
  if (!Number.isInteger(number) || number <= 0) return false;
  const issue = repo.issuesByNumber.get(number);
  if (!issue) {
    sendError(res, 404, 'Not Found');
    return true;
  }

  if (rest.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, issueJson(issue, repo), { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    if (method === 'PATCH') {
      if (!parseBodyJson(ctx)) return true;
      const body = ctx.json as Record<string, unknown>;
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
      if (Array.isArray(body.labels)) {
        const labels: Label[] = [];
        for (const raw of body.labels) {
          const name = typeof raw === 'string' ? raw : '';
          const found = repo.labels.get(name);
          if (!found) {
            sendError(res, 422, `Validation Failed: label "${name}" does not exist`);
            return true;
          }
          labels.push(found);
        }
        issue.labels = labels;
      }
      issue.updatedSeq = store.nextSeq();
      sendJson(res, 200, issueJson(issue, repo), { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    return false;
  }

  if (rest.length === 2 && rest[1] === 'comments') {
    if (method === 'GET') {
      const { page, link } = paginate(issue.comments.map((c) => commentJson(c, repo, issue)), ctx.query, ctx.path, host);
      sendJson(res, 200, page, { 'x-oauth-scopes': 'repo, read:org', ...linkHeader(link) });
      return true;
    }
    if (method === 'POST') {
      if (!parseBodyJson(ctx)) return true;
      const body = ctx.json as Record<string, unknown>;
      const text = typeof body.body === 'string' ? body.body : '';
      if (text === '') {
        sendError(res, 422, 'Validation Failed: body is required');
        return true;
      }
      const comment: Comment = { id: store.nextGlobalId++, body: text, user: VIEWER_LOGIN, createdSeq: store.nextSeq() };
      issue.comments.push(comment);
      sendJson(res, 201, commentJson(comment, repo, issue), { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    return false;
  }

  return false;
}

function handlePulls(ctx: Ctx, repo: Repo, rest: readonly string[]): boolean {
  const { req, res } = ctx;
  const method = req.method ?? 'GET';
  const host = req.headers.host ?? 'localhost';

  if (rest.length === 0) {
    if (method === 'GET') {
      const state = ctx.query.get('state') ?? 'open';
      let list = [...repo.pulls];
      if (state === 'open') list = list.filter((p) => p.state === 'open');
      else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
      list.sort((a, b) => b.createdSeq - a.createdSeq);
      const { page, link } = paginate(list.map((p) => pullJson(p, repo)), ctx.query, ctx.path, host);
      sendJson(res, 200, page, { 'x-oauth-scopes': 'repo, read:org', ...linkHeader(link) });
      return true;
    }
    if (method === 'POST') {
      if (!parseBodyJson(ctx)) return true;
      const body = ctx.json as Record<string, unknown>;
      const head = typeof body.head === 'string' ? body.head : '';
      const base = typeof body.base === 'string' ? body.base : repo.defaultBranch;
      const title = typeof body.title === 'string' ? body.title : '';
      if (head === '' || title === '') {
        sendError(res, 422, 'Validation Failed: head and title are required');
        return true;
      }
      const headSha = resolveRef(repo, head);
      const baseSha = resolveRef(repo, base);
      if (headSha === null || baseSha === null) {
        sendError(res, 422, 'Validation Failed: head or base branch does not exist');
        return true;
      }
      const duplicate = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
      if (duplicate) {
        sendError(res, 422, 'Validation Failed: a pull request already exists for this branch');
        return true;
      }
      const seq = store.nextSeq();
      const pull: Pull = {
        id: store.nextGlobalId++,
        number: repo.nextNumber++,
        title,
        body: typeof body.body === 'string' ? body.body : '',
        state: 'open',
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        headRef: head,
        baseRef: base,
        headSha,
        baseSha,
        createdSeq: seq,
        updatedSeq: seq,
      };
      repo.pulls.push(pull);
      repo.pullsByNumber.set(pull.number, pull);
      sendJson(res, 201, pullJson(pull, repo), { 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    return false;
  }

  const number = Number.parseInt(rest[0] ?? '', 10);
  if (!Number.isInteger(number) || number <= 0) return false;
  const pull = repo.pullsByNumber.get(number);
  if (!pull) {
    sendError(res, 404, 'Not Found');
    return true;
  }

  if (rest.length === 1 && method === 'GET') {
    sendJson(res, 200, pullJson(pull, repo), { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }

  if (rest.length === 2 && rest[1] === 'files' && method === 'GET') {
    const base = mergeBase(repo, pull.baseSha, pull.headSha);
    const baseTree = base === null ? null : parseCommit(repo.objects.get(base)?.data ?? Buffer.alloc(0)).tree;
    const headTree = parseCommit(repo.objects.get(pull.headSha)?.data ?? Buffer.alloc(0)).tree;
    const files = diffTrees(repo, baseTree, headTree).map((d) => ({
      sha: '',
      filename: d.filename,
      status: d.status,
      additions: d.additions,
      deletions: d.deletions,
      changes: d.additions + d.deletions,
      blob_url: '',
      raw_url: '',
      contents_url: '',
      patch: '',
    }));
    sendJson(res, 200, files, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }

  if (rest.length === 2 && rest[1] === 'merge' && method === 'PUT') {
    if (pull.state !== 'open') {
      sendError(res, 405, 'Pull request is already closed');
      return true;
    }
    const mergeSha = squashMerge(repo, pull);
    if (mergeSha === null) {
      sendError(res, 405, 'Merge conflict');
      return true;
    }
    pull.state = 'closed';
    pull.merged = true;
    pull.mergedAt = isoAt(store.nextSeq());
    pull.mergeCommitSha = mergeSha;
    pull.updatedSeq = store.nextSeq();
    sendJson(res, 200, { sha: mergeSha, merged: true, message: `Pull request successfully merged and closed` }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }

  return false;
}

// ---------------------------------------------------------------------------------------------
// Git smart HTTP
// ---------------------------------------------------------------------------------------------

const AGENT_NAME = 'makefun-git-forge/1.0.0';

/** Ordered ref entries for advertisement, as `{oid, ref, peeled?}`. */
function advertisementRefs(repo: Repo): { oid: string; ref: string; peeled?: string }[] {
  const out: { oid: string; ref: string; peeled?: string }[] = [];
  const defaultRef = `refs/heads/${repo.defaultBranch}`;
  const sorted = [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  // HEAD first (v0 expects the HEAD line with the symref capability).
  const defaultTip = repo.refs.get(defaultRef);
  if (defaultTip !== undefined) out.push({ oid: defaultTip, ref: 'HEAD' });
  for (const [ref, oid] of sorted) {
    const entry: { oid: string; ref: string; peeled?: string } = { oid, ref };
    const object = repo.objects.get(oid);
    if (object?.type === 'tag') {
      const peeled = peelToCommit(repo, oid);
      if (peeled !== oid) entry.peeled = peeled;
    }
    out.push(entry);
  }
  return out;
}

function sendGitBytes(res: ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': String(body.length),
    'x-github-request-id': nextRequestId(),
    'cache-control': 'no-cache, max-age=0, must-revalidate',
  });
  res.end(body);
}

function handleGitInfoRefs(ctx: Ctx, repo: Repo | null): boolean {
  const { req, res } = ctx;
  const service = ctx.query.get('service') ?? '';
  if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
    res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8', 'x-github-request-id': nextRequestId() });
    res.end('unknown service\n');
    return true;
  }
  if (!repo) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8', 'x-github-request-id': nextRequestId() });
    res.end('Not Found\n');
    return true;
  }
  const isV2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '') === 'version=2';
  const parts: Buffer[] = [];
  if (service === 'git-upload-pack') {
    parts.push(pktLine(`# service=git-upload-pack\n`));
    parts.push(pktFlush());
    if (isV2) {
      parts.push(pktLine('version 2\n'));
      parts.push(pktLine('ls-refs=unborn\n'));
      parts.push(pktLine('fetch=shallow filter\n'));
      parts.push(pktLine('object-format=sha1\n'));
      parts.push(pktLine(`agent=${AGENT_NAME}\n`));
      parts.push(pktFlush());
    } else {
      const refs = advertisementRefs(repo);
      const caps = `side-band-64k thin-pack ofs-delta shallow multi_ack_detailed symref=HEAD:refs/heads/${repo.defaultBranch} agent=${AGENT_NAME} object-format=sha1`;
      if (refs.length === 0) {
        parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
      } else {
        let first = true;
        for (const entry of refs) {
          const refName = entry.ref;
          const suffix = first ? `\0${caps}` : '';
          first = false;
          parts.push(pktLine(`${entry.oid} ${refName}${suffix}\n`));
          if (entry.peeled !== undefined) parts.push(pktLine(`${entry.peeled} ${refName}^{}\n`));
        }
      }
      parts.push(pktFlush());
    }
    sendGitBytes(res, 200, 'application/x-git-upload-pack-advertisement', Buffer.concat(parts));
    return true;
  }
  // git-receive-pack advertisement (v0 only).
  parts.push(pktLine('# service=git-receive-pack\n'));
  parts.push(pktFlush());
  const refs = advertisementRefs(repo);
  const caps = `report-status side-band-64k delete-refs ofs-delta agent=${AGENT_NAME} object-format=sha1`;
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    let first = true;
    for (const entry of refs) {
      const refName = entry.ref;
      const suffix = first ? `\0${caps}` : '';
      first = false;
      parts.push(pktLine(`${entry.oid} ${refName}${suffix}\n`));
      if (entry.peeled !== undefined) parts.push(pktLine(`${entry.peeled} ${refName}^{}\n`));
    }
  }
  parts.push(pktFlush());
  sendGitBytes(res, 200, 'application/x-git-receive-pack-advertisement', Buffer.concat(parts));
  return true;
}

interface FetchPlan {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | null;
  deepenSince: number | null;
  thinPack: boolean;
}

/** The shallow-boundary set for a fetch: commits at generation depth-1 from the wants. */
function computeFetch(
  repo: Repo,
  plan: FetchPlan,
): { packObjects: GitObject[]; shallow: string[]; unshallow: string[] } {
  const clientShallow = new Set(plan.shallow);

  // Objects the client already has: the closure of its haves, with traversal stopping
  // at its shallow boundaries (it has those commits, but not their parents).
  const haveClosure = new Set<string>();
  const haveQueue = [...plan.haves];
  while (haveQueue.length > 0) {
    const oid = haveQueue.pop() as string;
    if (haveClosure.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (!object) continue;
    haveClosure.add(oid);
    if (object.type === 'commit') {
      if (clientShallow.has(oid)) continue;
      const commit = parseCommit(object.data);
      haveQueue.push(commit.tree);
      for (const parent of commit.parents) haveQueue.push(parent);
    } else if (object.type === 'tag') {
      haveQueue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) if (entry.mode !== '160000') haveQueue.push(entry.oid);
    }
  }

  // Walk the wants, tracking generation depth from the want tips. A commit at the depth
  // limit (or older than deepen-since) is a shallow boundary: include it, not its parents.
  // A have that is not a client shallow boundary stops the walk; a client shallow boundary
  // is descended past (its parents are new to the client) but never re-sent itself.
  const include = new Set<string>();
  const shallowSet = new Set<string>();
  const unshallowSet = new Set<string>();
  const generations = new Map<string, number>();
  const queue: string[] = [];
  const addTreeClosure = (treeOid: string): void => {
    const stack = [treeOid];
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (include.has(oid)) continue;
      const object = repo.objects.get(oid);
      if (!object) continue;
      include.add(oid);
      if (object.type === 'tree') {
        for (const entry of parseTree(object.data)) if (entry.mode !== '160000') stack.push(entry.oid);
      }
    }
  };
  for (const want of plan.wants) {
    const object = repo.objects.get(want);
    if (!object) continue;
    if (object.type === 'tag') {
      include.add(want);
      const target = parseTag(object.data).object;
      if (!generations.has(target)) {
        generations.set(target, 0);
        queue.push(target);
      }
    } else if (object.type === 'commit') {
      if (!generations.has(want)) {
        generations.set(want, 0);
        queue.push(want);
      }
    } else {
      include.add(want);
    }
  }
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    const generation = generations.get(oid) as number;
    const object = repo.objects.get(oid);
    if (!object) continue;
    if (object.type === 'tag') {
      include.add(oid);
      const target = parseTag(object.data).object;
      if (!generations.has(target)) {
        generations.set(target, generation);
        queue.push(target);
      }
      continue;
    }
    if (object.type !== 'commit') {
      include.add(oid);
      continue;
    }
    const commit = parseCommit(object.data);
    let boundary = plan.depth !== null && generation >= plan.depth - 1;
    if (!boundary && plan.deepenSince !== null) {
      const ts = Date.parse(parseWho(commit.committer).date) / 1000;
      if (Number.isFinite(ts) && ts < plan.deepenSince) boundary = true;
    }
    if (boundary) shallowSet.add(oid);
    if (clientShallow.has(oid) && !boundary) unshallowSet.add(oid);
    const isHave = haveClosure.has(oid);
    if (!isHave) {
      include.add(oid);
      addTreeClosure(commit.tree);
    } else if (!clientShallow.has(oid)) {
      // The client has this commit and its history: stop here.
      continue;
    }
    // Descend past client shallow boundaries (and past non-have commits) within depth.
    if (!boundary) {
      for (const parent of commit.parents) {
        if (!generations.has(parent)) {
          generations.set(parent, generation + 1);
          queue.push(parent);
        }
      }
    }
  }

  const packObjects: GitObject[] = [];
  for (const oid of include) {
    if (haveClosure.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object) packObjects.push(object);
  }
  return {
    packObjects,
    shallow: [...shallowSet].filter((oid) => include.has(oid) && !haveClosure.has(oid)).sort(),
    unshallow: [...unshallowSet].sort(),
  };
}

function handleGitUploadPack(ctx: Ctx, repo: Repo | null): boolean {
  const { req, res } = ctx;
  if (!repo) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8', 'x-github-request-id': nextRequestId() });
    res.end('Not Found\n');
    return true;
  }
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  let packets: Pkt[];
  try {
    packets = decodePktLines(ctx.body);
  } catch {
    res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8', 'x-github-request-id': nextRequestId() });
    res.end('bad request\n');
    return true;
  }
  const lines = pktTexts(packets);
  if (!isV2) {
    // v0 fetch: `want <oid> [caps]`, `have`, `shallow`, `deepen`, `done`.
    const plan: FetchPlan = { wants: [], haves: [], shallow: [], depth: null, deepenSince: null, thinPack: false };
    for (const line of lines) {
      const text = line.trim();
      if (text.startsWith('want ')) plan.wants.push(text.slice(5).split(' ')[0] as string);
      else if (text.startsWith('have ')) plan.haves.push(text.slice(5).trim());
      else if (text.startsWith('shallow ')) plan.shallow.push(text.slice(8).trim());
      else if (text.startsWith('deepen ')) {
        const n = Number.parseInt(text.slice(7), 10);
        if (Number.isFinite(n)) plan.depth = n;
      }
    }
    const result = computeFetch(repo, plan);
    const out: Buffer[] = [];
    out.push(pktLine('NAK\n'));
    for (const oid of result.shallow) out.push(pktLine(`shallow ${oid}\n`));
    for (const oid of result.unshallow) out.push(pktLine(`unshallow ${oid}\n`));
    out.push(pktFlush());
    const pack = writePack(result.packObjects);
    sendPackSideband(res, pack);
    return true;
  }
  // Protocol v2.
  const commandLine = lines[0]?.trim() ?? '';
  if (commandLine === 'command=ls-refs') {
    const prefixes: string[] = [];
    let peel = false;
    let symrefs = false;
    let unborn = false;
    for (const line of lines.slice(1)) {
      const text = line.trim();
      if (text.startsWith('ref-prefix ')) prefixes.push(text.slice('ref-prefix '.length));
      else if (text === 'peel') peel = true;
      else if (text === 'symrefs') symrefs = true;
      else if (text === 'unborn') unborn = true;
    }
    const out: Buffer[] = [];
    const defaultRef = `refs/heads/${repo.defaultBranch}`;
    const matches = (ref: string): boolean => prefixes.length === 0 || prefixes.some((p) => ref.startsWith(p));
    const sorted = [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    let emitted = false;
    if (matches('HEAD') && repo.refs.has(defaultRef)) {
      const tip = repo.refs.get(defaultRef) as string;
      let line = `${tip} HEAD`;
      if (symrefs) line += ` symref-target:${defaultRef}`;
      out.push(pktLine(`${line}\n`));
      emitted = true;
    }
    for (const [ref, oid] of sorted) {
      if (!matches(ref)) continue;
      let line = `${oid} ${ref}`;
      const object = repo.objects.get(oid);
      if (peel && object?.type === 'tag') {
        const peeled = peelToCommit(repo, oid);
        if (peeled !== oid) line += ` peeled:${peeled}`;
      }
      out.push(pktLine(`${line}\n`));
      emitted = true;
    }
    if (!emitted && unborn && !repo.refs.has(defaultRef)) {
      out.push(pktLine(`unborn HEAD symref-target:${defaultRef}\n`));
    }
    out.push(pktFlush());
    sendGitBytes(res, 200, 'application/x-git-upload-pack-result', Buffer.concat(out));
    return true;
  }
  if (commandLine === 'command=fetch') {
    const plan: FetchPlan = { wants: [], haves: [], shallow: [], depth: null, deepenSince: null, thinPack: false };
    let done = false;
    for (const line of lines.slice(1)) {
      const text = line.trim();
      if (text === 'thin-pack') plan.thinPack = true;
      else if (text === 'done') done = true;
      else if (text.startsWith('want ')) plan.wants.push(text.slice(5).trim());
      else if (text.startsWith('have ')) plan.haves.push(text.slice(5).trim());
      else if (text.startsWith('shallow ')) plan.shallow.push(text.slice(8).trim());
      else if (text.startsWith('deepen ')) {
        const n = Number.parseInt(text.slice(7), 10);
        if (Number.isFinite(n)) plan.depth = n;
      } else if (text.startsWith('deepen-since ')) {
        const ts = Date.parse(text.slice('deepen-since '.length));
        if (Number.isFinite(ts)) plan.deepenSince = Math.floor(ts / 1000);
      }
    }
    const cacheKey = JSON.stringify([repo.name, plan.wants, plan.haves, plan.shallow, plan.depth, plan.deepenSince]);
    const cached = store.packCache.get(cacheKey);
    let pack: Buffer;
    let shallow: string[];
    let unshallow: string[];
    if (cached !== undefined) {
      pack = cached.pack;
      shallow = cached.shallow;
      unshallow = cached.unshallow;
    } else {
      const result = computeFetch(repo, plan);
      pack = writePack(result.packObjects);
      shallow = result.shallow;
      unshallow = result.unshallow;
      if (store.packCache.size >= 16) store.packCache.clear();
      store.packCache.set(cacheKey, { pack, shallow, unshallow });
    }
    // The acknowledgments section exists only when the client sent haves. Real git's
    // fetch client reads it only in that case, and dies on it otherwise. The section
    // lists the haves that are ancestors of the wants (ACK) and `ready` when the
    // negotiation is complete, terminated by a delim packet; the packfile follows in
    // the same response. (A NAK would make real git expect the round to end and send
    // a second round, so ACK the common haves instead.)
    const out: Buffer[] = [];
    if (plan.haves.length > 0) {
      const wantClosure = new Set<string>();
      for (const want of plan.wants) {
        for (const oid of collectReachable([want], (oid) => repo.objects.get(oid))) wantClosure.add(oid);
      }
      const common = plan.haves.filter((have) => wantClosure.has(have));
      out.push(pktLine('acknowledgments\n'));
      if (common.length === 0) {
        out.push(pktLine('NAK\n'));
        out.push(pktFlush());
        if (!done) {
          // No common commits and the client is still negotiating: end this round
          // so it can come back with `done`. (The suite's client always sends `done`.)
          out.push(pktResponseEnd());
          sendGitBytes(res, 200, 'application/x-git-upload-pack-result', Buffer.concat(out));
          return true;
        }
      } else {
        for (const oid of common) out.push(pktLine(`ACK ${oid}\n`));
        out.push(pktLine('ready\n'));
        out.push(pktDelim());
      }
    }
    out.push(pktLine('shallow-info\n'));
    for (const oid of shallow) out.push(pktLine(`shallow ${oid}\n`));
    for (const oid of unshallow) out.push(pktLine(`unshallow ${oid}\n`));
    out.push(pktFlush());
    out.push(pktLine('packfile\n'));
    sendGitBytes(res, 200, 'application/x-git-upload-pack-result', Buffer.concat([...out, ...sidebandChunks(pack as Buffer)]));
    return true;
  }
  res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8', 'x-github-request-id': nextRequestId() });
  res.end('unknown command\n');
  return true;
}

/** Split pack bytes into sideband band-1 pkt-lines (32 KiB chunks), then a flush. */
function sidebandChunks(pack: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const chunkSize = 32768;
  for (let offset = 0; offset < pack.length; offset += chunkSize) {
    const slice = pack.subarray(offset, Math.min(pack.length, offset + chunkSize));
    const framed = Buffer.concat([Buffer.from([1]), slice]);
    out.push(pktLine(framed));
  }
  out.push(pktFlush());
  return out;
}

function sendPackSideband(res: ServerResponse, pack: Buffer): void {
  sendGitBytes(res, 200, 'application/x-git-upload-pack-result', Buffer.concat(sidebandChunks(pack)));
}

interface ReceiveCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

function handleGitReceivePack(ctx: Ctx, repo: Repo | null): boolean {
  const { res } = ctx;
  if (!repo) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8', 'x-github-request-id': nextRequestId() });
    res.end('Not Found\n');
    return true;
  }
  // The command block ends at the first flush packet; the rest is the packfile.
  let commands: ReceiveCommand[] = [];
  let packStart = ctx.body.length;
  let malformed = false;
  try {
    let offset = 0;
    while (offset < ctx.body.length) {
      if (offset + 4 > ctx.body.length) throw new Error('truncated');
      const head = ctx.body.subarray(offset, offset + 4).toString('ascii');
      if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error('bad pkt-line');
      const len = Number.parseInt(head, 16);
      if (len === 0) {
        packStart = offset + 4;
        break;
      }
      if (len < 4 || offset + len > ctx.body.length) throw new Error('bad pkt-line length');
      const payload = ctx.body.subarray(offset + 4, offset + len).toString('utf8');
      const nul = payload.indexOf('\0');
      const line = (nul >= 0 ? payload.slice(0, nul) : payload).trim();
      const parts = line.split(' ');
      if (parts.length !== 3 || !isOid(parts[0] as string) || !isOid(parts[1] as string)) throw new Error('bad command line');
      commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts[2] as string });
      offset += len;
    }
  } catch {
    malformed = true;
  }
  const results: { ref: string; ok: boolean; reason?: string }[] = [];
  if (!malformed && packStart < ctx.body.length) {
    try {
      const { objects } = readPack(ctx.body.subarray(packStart), (oid) => repo.objects.get(oid));
      for (const [oid, object] of objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, object);
      }
    } catch {
      malformed = true;
    }
  } else if (!malformed && commands.length > 0 && packStart >= ctx.body.length) {
    // A create/update command list without a pack: nothing to unpack.
  }
  if (!malformed) {
    for (const command of commands) {
      const current = repo.refs.get(command.ref) ?? ZERO_OID;
      if (command.newOid === ZERO_OID) {
        // Delete.
        if (command.oldOid !== current) {
          results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
        } else {
          repo.refs.delete(command.ref);
          results.push({ ref: command.ref, ok: true });
        }
        continue;
      }
      if (command.oldOid === ZERO_OID) {
        if (current !== ZERO_OID) {
          results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
          continue;
        }
        const object = repo.objects.get(command.newOid);
        if (!object) {
          results.push({ ref: command.ref, ok: false, reason: 'object not found' });
          continue;
        }
        repo.refs.set(command.ref, command.newOid);
        if (object.type === 'commit') repo.commitSeq.set(command.newOid, store.nextSeq());
        results.push({ ref: command.ref, ok: true });
        continue;
      }
      if (command.oldOid !== current) {
        results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }
      if (!isAncestor(repo, command.oldOid, command.newOid)) {
        results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }
      repo.refs.set(command.ref, command.newOid);
      results.push({ ref: command.ref, ok: true });
    }
  }
  const out: Buffer[] = [];
  const report: string[] = [];
  if (malformed) {
    report.push('unpack error\n');
  } else {
    report.push('unpack ok\n');
    for (const result of results) {
      report.push(result.ok ? `ok ${result.ref}\n` : `ng ${result.ref} ${result.reason ?? 'rejected'}\n`);
    }
  }
  const reportBytes = Buffer.concat([...report.map((line) => pktLine(line)), pktFlush()]);
  out.push(pktLine(Buffer.concat([Buffer.from([1]), reportBytes])));
  out.push(pktFlush());
  sendGitBytes(res, 200, 'application/x-git-receive-pack-result', Buffer.concat(out));
  return true;
}

function handleGit(ctx: Ctx): boolean {
  const seg = ctx.segments;
  // /{owner}/{repo}.git/info/refs, /{owner}/{repo}.git/git-upload-pack, /{owner}/{repo}.git/git-receive-pack
  if (seg.length < 3) return false;
  const repoSegment = seg[1] ?? '';
  if (!repoSegment.endsWith('.git')) return false;
  const owner = decodeURIComponent(seg[0] as string);
  const repoName = decodeURIComponent(repoSegment.slice(0, -4));
  const repo = store.getRepo(repoName);
  if (!repo || repo.owner !== owner) {
    // Missing repos answer 404 (never 403) on the git endpoints too.
    if (seg[2] === 'info' && seg[3] === 'refs') {
      const { res } = ctx;
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8', 'x-github-request-id': nextRequestId() });
      res.end('Not Found\n');
      return true;
    }
    return handleGitEndpoint(ctx, null);
  }
  return handleGitEndpoint(ctx, repo);
}

function handleGitEndpoint(ctx: Ctx, repo: Repo | null): boolean {
  const seg = ctx.segments;
  const method = ctx.req.method ?? 'GET';
  if (seg[2] === 'info' && seg[3] === 'refs' && method === 'GET') return handleGitInfoRefs(ctx, repo);
  if (seg[2] === 'git-upload-pack' && method === 'POST') return handleGitUploadPack(ctx, repo);
  if (seg[2] === 'git-receive-pack' && method === 'POST') return handleGitReceivePack(ctx, repo);
  return false;
}

// ---------------------------------------------------------------------------------------------
// GraphQL v4
// ---------------------------------------------------------------------------------------------

type GqlValue =
  | null
  | boolean
  | number
  | string
  | GqlValue[]
  | { [key: string]: GqlValue };

interface GqlObject {
  __typename: string;
  [key: string]: unknown;
}

type GqlSelection =
  | { kind: 'field'; name: string; alias: string | null; args: Record<string, GqlValue>; selections: GqlSelection[] }
  | { kind: 'fragment'; typeCondition: string | null; selections: GqlSelection[] }
  | { kind: 'named'; name: string };

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  variables: Record<string, { type: string; defaultValue?: GqlValue }>;
  selections: GqlSelection[];
}

interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, { typeCondition: string | null; selections: GqlSelection[] }>;
}

type Token =
  | { kind: 'name'; value: string }
  | { kind: 'int'; value: string }
  | { kind: 'string'; value: string }
  | { kind: 'punct'; value: string }
  | { kind: 'eof' };

function lexGraphQL(source: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && source.slice(i, i + 3) === '...') {
      tokens.push({ kind: 'punct', value: '...' });
      i += 3;
      continue;
    }
    if ('{}()[]:!=$@&|'.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      let value = '';
      i += 1;
      while (i < source.length && source[i] !== '"') {
        if (source[i] === '\\' && i + 1 < source.length) {
          const next = source[i + 1] as string;
          const escapes: Record<string, string> = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f' };
          value += escapes[next] ?? next;
          i += 2;
        } else {
          value += source[i];
          i += 1;
        }
      }
      i += 1;
      tokens.push({ kind: 'string', value });
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      if (source[j] === '-') j += 1;
      while (j < source.length && /[0-9.]/.test(source[j] as string)) j += 1;
      tokens.push({ kind: 'int', value: source.slice(i, j) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < source.length && /[A-Za-z0-9_]/.test(source[j] as string)) j += 1;
      tokens.push({ kind: 'name', value: source.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)} in GraphQL document`);
  }
  tokens.push({ kind: 'eof' });
  return tokens;
}

class GqlParser {
  #tokens: Token[];
  #pos = 0;

  constructor(source: string) {
    this.#tokens = lexGraphQL(source);
  }

  #peek(): Token {
    return this.#tokens[this.#pos] as Token;
  }

  #next(): Token {
    const token = this.#tokens[this.#pos] as Token;
    this.#pos += 1;
    return token;
  }

  #expectPunct(value: string): void {
    const token = this.#next();
    if (token.kind !== 'punct' || token.value !== value) throw new Error(`expected ${value}`);
  }

  #expectName(value?: string): string {
    const token = this.#next();
    if (token.kind !== 'name') throw new Error('expected name');
    if (value !== undefined && token.value !== value) throw new Error(`expected ${value}`);
    return token.value;
  }

  #skipDirectives(): void {
    while (this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === '@') {
      this.#next();
      this.#expectName();
      if (this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === '(') this.#parseArguments({});
    }
  }

  parseDocument(): GqlDocument {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, { typeCondition: string | null; selections: GqlSelection[] }>();
    while (this.#peek().kind !== 'eof') {
      const token = this.#peek();
      if (token.kind === 'punct' && token.value === '{') {
        operations.push({ kind: 'query', name: null, variables: {}, selections: this.#parseSelectionSet() });
        continue;
      }
      if (token.kind === 'name' && token.value === 'fragment') {
        this.#next();
        const name = this.#expectName();
        this.#expectName('on');
        const typeCondition = this.#expectName();
        this.#skipDirectives();
        fragments.set(name, { typeCondition, selections: this.#parseSelectionSet() });
        continue;
      }
      if (token.kind === 'name' && (token.value === 'query' || token.value === 'mutation')) {
        const kind = token.value as 'query' | 'mutation';
        this.#next();
        let name: string | null = null;
        if (this.#peek().kind === 'name') {
          const nameToken = this.#next();
          if (nameToken.kind === 'name') name = nameToken.value;
        }
        const variables = this.#parseVariableDefinitions();
        this.#skipDirectives();
        operations.push({ kind, name, variables, selections: this.#parseSelectionSet() });
        continue;
      }
      throw new Error('unexpected token in GraphQL document');
    }
    return { operations, fragments };
  }

  #parseVariableDefinitions(): Record<string, { type: string; defaultValue?: GqlValue }> {
    const variables: Record<string, { type: string; defaultValue?: GqlValue }> = {};
    if (this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === '(') {
      this.#next();
      while (!(this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === ')')) {
        this.#expectPunct('$');
        const name = this.#expectName();
        this.#expectPunct(':');
        const type = this.#parseTypeName();
        let defaultValue: GqlValue | undefined;
        if (this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === '=') {
          this.#next();
          defaultValue = this.#parseValue({});
        }
        this.#skipDirectives();
        variables[name] = { type, defaultValue };
      }
      this.#expectPunct(')');
    }
    return variables;
  }

  #parseTypeName(): string {
    let type = '';
    if (this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === '[') {
      this.#next();
      type = `[${this.#parseTypeName()}]`;
    } else {
      type = this.#expectName();
    }
    while (this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === '!') {
      this.#next();
      type += '!';
    }
    return type;
  }

  #parseSelectionSet(): GqlSelection[] {
    this.#expectPunct('{');
    const selections: GqlSelection[] = [];
    while (!(this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === '}')) {
      const token = this.#peek();
      if (token.kind === 'punct' && token.value === '...') {
        this.#next();
        const next = this.#peek();
        if (next.kind === 'name' && next.value === 'on') {
          this.#next();
          const typeCondition = this.#expectName();
          this.#skipDirectives();
          selections.push({ kind: 'fragment', typeCondition, selections: this.#parseSelectionSet() });
        } else if (next.kind === 'name') {
          const nameToken = this.#next();
          const name = nameToken.kind === 'name' ? nameToken.value : '';
          this.#skipDirectives();
          selections.push({ kind: 'named', name });
        } else {
          selections.push({ kind: 'fragment', typeCondition: null, selections: this.#parseSelectionSet() });
        }
        continue;
      }
      const name = this.#expectName();
      let alias: string | null = null;
      let fieldName = name;
      if (this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === ':') {
        this.#next();
        alias = name;
        fieldName = this.#expectName();
      }
      const args = this.#parseArguments({});
      this.#skipDirectives();
      let childSelections: GqlSelection[] = [];
      if (this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === '{') {
        childSelections = this.#parseSelectionSet();
      }
      selections.push({ kind: 'field', name: fieldName, alias, args, selections: childSelections });
    }
    this.#expectPunct('}');
    return selections;
  }

  #parseArguments(variables: Record<string, GqlValue>): Record<string, GqlValue> {
    const args: Record<string, GqlValue> = {};
    if (this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === '(') {
      this.#next();
      while (!(this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === ')')) {
        const name = this.#expectName();
        this.#expectPunct(':');
        args[name] = this.#parseValue(variables);
      }
      this.#expectPunct(')');
    }
    return args;
  }

  #parseValue(variables: Record<string, GqlValue>): GqlValue {
    const token = this.#next();
    if (token.kind === 'punct' && token.value === '$') {
      const name = this.#expectName();
      return { __variable: name } as unknown as GqlValue;
    }
    if (token.kind === 'punct' && token.value === '[') {
      const list: GqlValue[] = [];
      while (!(this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === ']')) {
        list.push(this.#parseValue(variables));
      }
      this.#expectPunct(']');
      return list;
    }
    if (token.kind === 'punct' && token.value === '{') {
      const object: { [key: string]: GqlValue } = {};
      while (!(this.#peek().kind === 'punct' && (this.#peek() as { value: string }).value === '}')) {
        const name = this.#expectName();
        this.#expectPunct(':');
        object[name] = this.#parseValue(variables);
      }
      this.#expectPunct('}');
      return object;
    }
    if (token.kind === 'string') return token.value;
    if (token.kind === 'int') return Number(token.value);
    if (token.kind === 'name') {
      if (token.value === 'true') return true;
      if (token.value === 'false') return false;
      if (token.value === 'null') return null;
      return token.value;
    }
    throw new Error('unexpected value in GraphQL document');
  }
}

function resolveVariables(
  value: GqlValue,
  variables: Record<string, GqlValue>,
  defaults: Record<string, { type: string; defaultValue?: GqlValue }>,
): GqlValue {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const object = value as { [key: string]: GqlValue };
    if (typeof object.__variable === 'string') {
      const name = object.__variable;
      if (name in variables) return variables[name] as GqlValue;
      const def = defaults[name];
      if (def?.defaultValue !== undefined) return def.defaultValue;
      return null;
    }
    const out: { [key: string]: GqlValue } = {};
    for (const [key, entry] of Object.entries(object)) out[key] = resolveVariables(entry, variables, defaults);
    return out;
  }
  if (Array.isArray(value)) return value.map((entry) => resolveVariables(entry, variables, defaults));
  return value;
}

function encodeCursor(number: number): string {
  return b64encode(`cursor:${number}`);
}

function decodeCursor(cursor: string | null | undefined): number | null {
  if (typeof cursor !== 'string' || cursor === '') return null;
  try {
    const text = b64decode(cursor).toString('utf8');
    if (!text.startsWith('cursor:')) return null;
    const number = Number.parseInt(text.slice('cursor:'.length), 10);
    return Number.isInteger(number) ? number : null;
  } catch {
    return null;
  }
}

function itemNumber(item: GqlObject): number {
  const value = item.number;
  return typeof value === 'number' ? value : 0;
}

function pageInfoFor(ordered: readonly GqlObject[], sliced: readonly GqlObject[]): GqlObject {
  const last = sliced[sliced.length - 1];
  return {
    __typename: 'PageInfo',
    hasNextPage: ordered.length > sliced.length,
    hasPreviousPage: false,
    startCursor: sliced.length > 0 ? encodeCursor(itemNumber(sliced[0] as GqlObject)) : null,
    endCursor: last ? encodeCursor(itemNumber(last)) : null,
  };
}

function connectionOf(
  kind: string,
  ordered: readonly GqlObject[],
  first: number | null,
  after: string | null,
): GqlObject {
  let startIndex = 0;
  const afterNumber = decodeCursor(after);
  if (afterNumber !== null) {
    const index = ordered.findIndex((item) => itemNumber(item) === afterNumber);
    if (index >= 0) startIndex = index + 1;
  }
  const limit = first === null ? ordered.length : Math.max(0, first);
  const sliced = ordered.slice(startIndex, startIndex + limit);
  const pageInfo = pageInfoFor(ordered.slice(startIndex), sliced);
  return {
    __typename: kind,
    nodes: sliced,
    edges: sliced.map((item) => ({ __typename: `${kind}Edge`, node: item, cursor: encodeCursor(itemNumber(item)) })),
    pageInfo,
    totalCount: ordered.length,
  };
}

// The fields each introspectable type exposes (used by `__type { fields { name } }`).
const TYPE_FIELDS: Readonly<Record<string, readonly string[]>> = {
  Query: ['viewer', 'repository', 'node', 'search'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  User: ['id', 'databaseId', 'login', 'name', 'email', 'url', 'avatarUrl'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'url', 'description', 'createdAt', 'updatedAt'],
  Issue: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'url', 'createdAt', 'updatedAt', 'author', 'repository', 'comments'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  IssueEdge: ['node', 'cursor'],
  PullRequest: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'files', 'url', 'createdAt', 'updatedAt', 'author', 'repository'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestEdge: ['node', 'cursor'],
  PullRequestFile: ['path', 'additions', 'deletions', 'changeType'],
  PullRequestFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestFileEdge: ['node', 'cursor'],
  Ref: ['name', 'target', 'prefix'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  IssueComment: ['id', 'databaseId', 'body', 'createdAt', 'author'],
  IssueCommentEdge: ['node', 'cursor'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'clientMutationId'],
  __Type: ['name', 'kind', 'description', 'fields', 'enumValues', 'inputFields', 'ofType', 'interfaces', 'possibleTypes'],
  __Field: ['name', 'description', 'args', 'type', 'isDeprecated', 'deprecationReason'],
  __InputValue: ['name', 'description', 'type', 'defaultValue'],
  __EnumValue: ['name', 'description', 'isDeprecated', 'deprecationReason'],
  __Schema: ['queryType', 'mutationType', 'subscriptionType', 'types', 'directives'],
};

const SEARCH_TYPE_VALUES = ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'];

function typeObject(name: string): GqlObject {
  const isEnum = name === 'SearchType';
  const kind = isEnum ? 'ENUM' : name.startsWith('__') ? 'OBJECT' : 'OBJECT';
  return {
    __typename: '__Type',
    name,
    kind,
    description: null,
    fields: isEnum
      ? null
      : (TYPE_FIELDS[name] ?? []).map((fieldName) => ({
        __typename: '__Field',
        name: fieldName,
        description: null,
        args: [],
        type: { __typename: '__Type', name: 'String', kind: 'SCALAR', description: null, fields: null, enumValues: null, inputFields: null, ofType: null, interfaces: null, possibleTypes: null },
        isDeprecated: false,
        deprecationReason: null,
      })),
    enumValues: isEnum
      ? SEARCH_TYPE_VALUES.map((value) => ({ __typename: '__EnumValue', name: value, description: null, isDeprecated: false, deprecationReason: null }))
      : null,
    inputFields: null,
    ofType: null,
    interfaces: null,
    possibleTypes: null,
  };
}

function issueObject(issue: Issue, repo: Repo): GqlObject {
  return {
    __typename: 'Issue',
    __issue: issue,
    __repo: repo,
    id: store.globalId('Issue', issue.id),
    databaseId: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state === 'open' ? 'OPEN' : 'CLOSED',
    url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
    createdAt: isoAt(issue.createdSeq),
    updatedAt: isoAt(issue.updatedSeq),
  };
}

function pullObject(pull: Pull, repo: Repo): GqlObject {
  return {
    __typename: 'PullRequest',
    __pull: pull,
    __repo: repo,
    id: store.globalId('PullRequest', pull.id),
    databaseId: pull.id,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED',
    merged: pull.merged,
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
    headRefOid: resolveRef(repo, pull.headRef) ?? pull.headSha,
    baseRefOid: resolveRef(repo, pull.baseRef) ?? pull.baseSha,
    url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`,
    createdAt: isoAt(pull.createdSeq),
    updatedAt: isoAt(pull.updatedSeq),
  };
}

function repositoryObject(repo: Repo): GqlObject {
  return {
    __typename: 'Repository',
    __repo: repo,
    id: store.globalId('Repository', repo.id),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: `${repo.owner}/${repo.name}`,
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    url: `https://example.invalid/${repo.owner}/${repo.name}`,
    description: repo.description,
    createdAt: isoAt(repo.createdSeq),
    updatedAt: isoAt(repo.createdSeq),
  };
}

function viewerObject(): GqlObject {
  return {
    __typename: 'User',
    id: store.globalId('User', 1000),
    databaseId: 1000,
    login: VIEWER_LOGIN,
    name: VIEWER_NAME,
    email: VIEWER_EMAIL,
    url: `https://example.invalid/${VIEWER_LOGIN}`,
    avatarUrl: `https://avatars.example.invalid/${VIEWER_LOGIN}`,
  };
}

interface GqlContext {
  errors: { message: string }[];
  document: GqlDocument;
}

function resolveField(parent: GqlObject, field: string, args: Record<string, GqlValue>, ctx: GqlContext): unknown {
  const type = parent.__typename;
  // Top-level Query / Mutation.
  if (type === 'Query') {
    if (field === 'viewer') return viewerObject();
    if (field === 'repository') {
      const owner = typeof args.owner === 'string' ? args.owner : '';
      const name = typeof args.name === 'string' ? args.name : '';
      const repo = store.getRepo(name);
      if (!repo || repo.owner !== owner) return null;
      return repositoryObject(repo);
    }
    if (field === 'node') {
      const id = typeof args.id === 'string' ? args.id : '';
      const decoded = store.decodeGlobalId(id);
      if (!decoded) return null;
      if (decoded.kind === 'Repository') {
        const repo = [...store.repos.values()].find((r) => r.id === Number(decoded.internal));
        return repo ? repositoryObject(repo) : null;
      }
      if (decoded.kind === 'Issue') {
        const internal = Number(decoded.internal);
        for (const repo of store.repos.values()) {
          const issue = repo.issues.find((i) => i.id === internal);
          if (issue) return issueObject(issue, repo);
        }
        return null;
      }
      if (decoded.kind === 'PullRequest') {
        const internal = Number(decoded.internal);
        for (const repo of store.repos.values()) {
          const pull = repo.pulls.find((p) => p.id === internal);
          if (pull) return pullObject(pull, repo);
        }
        return null;
      }
      return null;
    }
    if (field === '__type') {
      const name = typeof args.name === 'string' ? args.name : '';
      if (!TYPE_FIELDS[name] && name !== 'SearchType') return null;
      return typeObject(name);
    }
    if (field === '__schema') {
      return {
        __typename: '__Schema',
        queryType: typeObject('Query'),
        mutationType: typeObject('Mutation'),
        subscriptionType: null,
        types: [],
        directives: [],
      };
    }
  }
  if (type === 'Mutation') {
    if (field === 'createIssue') {
      const input = (args.input ?? {}) as Record<string, GqlValue>;
      const repoId = typeof input.repositoryId === 'string' ? input.repositoryId : '';
      const decoded = store.decodeGlobalId(repoId);
      const repo = decoded?.kind === 'Repository' ? [...store.repos.values()].find((r) => r.id === Number(decoded.internal)) : undefined;
      if (!repo) {
        ctx.errors.push({ message: 'Could not resolve to a Repository with the global id provided.' });
        return { __typename: 'CreateIssuePayload', issue: null, clientMutationId: (input.clientMutationId as string | null) ?? null };
      }
      const title = typeof input.title === 'string' ? input.title : '';
      const seq = store.nextSeq();
      const issue: Issue = {
        id: store.nextGlobalId++,
        number: repo.nextNumber++,
        title,
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        labels: [],
        comments: [],
        createdSeq: seq,
        updatedSeq: seq,
      };
      repo.issues.push(issue);
      repo.issuesByNumber.set(issue.number, issue);
      return { __typename: 'CreateIssuePayload', issue: issueObject(issue, repo), clientMutationId: (input.clientMutationId as string | null) ?? null };
    }
    if (field === 'closeIssue') {
      const input = (args.input ?? {}) as Record<string, GqlValue>;
      const issueId = typeof input.issueId === 'string' ? input.issueId : '';
      const decoded = store.decodeGlobalId(issueId);
      let found: { issue: Issue; repo: Repo } | null = null;
      if (decoded?.kind === 'Issue') {
        for (const repo of store.repos.values()) {
          const issue = repo.issues.find((i) => i.id === Number(decoded.internal));
          if (issue) {
            found = { issue, repo };
            break;
          }
        }
      }
      if (!found) {
        ctx.errors.push({ message: 'Could not resolve to an Issue with the global id provided.' });
        return { __typename: 'CloseIssuePayload', issue: null, clientMutationId: (input.clientMutationId as string | null) ?? null };
      }
      found.issue.state = 'closed';
      found.issue.updatedSeq = store.nextSeq();
      return { __typename: 'CloseIssuePayload', issue: issueObject(found.issue, found.repo), clientMutationId: (input.clientMutationId as string | null) ?? null };
    }
    if (field === 'createPullRequest') {
      const input = (args.input ?? {}) as Record<string, GqlValue>;
      const repoId = typeof input.repositoryId === 'string' ? input.repositoryId : '';
      const decoded = store.decodeGlobalId(repoId);
      const repo = decoded?.kind === 'Repository' ? [...store.repos.values()].find((r) => r.id === Number(decoded.internal)) : undefined;
      const baseRefName = typeof input.baseRefName === 'string' ? input.baseRefName : '';
      const headRefName = typeof input.headRefName === 'string' ? input.headRefName : '';
      const title = typeof input.title === 'string' ? input.title : '';
      if (!repo) {
        ctx.errors.push({ message: 'Could not resolve to a Repository with the global id provided.' });
        return { __typename: 'CreatePullRequestPayload', pullRequest: null, clientMutationId: (input.clientMutationId as string | null) ?? null };
      }
      const headSha = resolveRef(repo, headRefName);
      const baseSha = resolveRef(repo, baseRefName);
      if (headSha === null || baseSha === null) {
        ctx.errors.push({ message: 'Validation Failed: head or base branch does not exist' });
        return { __typename: 'CreatePullRequestPayload', pullRequest: null, clientMutationId: (input.clientMutationId as string | null) ?? null };
      }
      const duplicate = repo.pulls.find((p) => p.state === 'open' && p.headRef === headRefName && p.baseRef === baseRefName);
      if (duplicate) {
        ctx.errors.push({ message: 'A pull request already exists for this branch' });
        return { __typename: 'CreatePullRequestPayload', pullRequest: null, clientMutationId: (input.clientMutationId as string | null) ?? null };
      }
      const seq = store.nextSeq();
      const pull: Pull = {
        id: store.nextGlobalId++,
        number: repo.nextNumber++,
        title,
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        headRef: headRefName,
        baseRef: baseRefName,
        headSha,
        baseSha,
        createdSeq: seq,
        updatedSeq: seq,
      };
      repo.pulls.push(pull);
      repo.pullsByNumber.set(pull.number, pull);
      return { __typename: 'CreatePullRequestPayload', pullRequest: pullObject(pull, repo), clientMutationId: (input.clientMutationId as string | null) ?? null };
    }
    if (field === 'mergePullRequest') {
      const input = (args.input ?? {}) as Record<string, GqlValue>;
      const pullRequestId = typeof input.pullRequestId === 'string' ? input.pullRequestId : '';
      const decoded = store.decodeGlobalId(pullRequestId);
      let found: { pull: Pull; repo: Repo } | null = null;
      if (decoded?.kind === 'PullRequest') {
        for (const repo of store.repos.values()) {
          const pull = repo.pulls.find((p) => p.id === Number(decoded.internal));
          if (pull) {
            found = { pull, repo };
            break;
          }
        }
      }
      if (!found) {
        ctx.errors.push({ message: 'Could not resolve to a PullRequest with the global id provided.' });
        return { __typename: 'MergePullRequestPayload', pullRequest: null, clientMutationId: (input.clientMutationId as string | null) ?? null };
      }
      const { pull, repo } = found;
      if (pull.state !== 'open') {
        ctx.errors.push({ message: 'Pull request is already closed' });
        return { __typename: 'MergePullRequestPayload', pullRequest: pullObject(pull, repo), clientMutationId: (input.clientMutationId as string | null) ?? null };
      }
      const mergeSha = squashMerge(repo, pull);
      if (mergeSha === null) {
        ctx.errors.push({ message: 'Merge conflict' });
        return { __typename: 'MergePullRequestPayload', pullRequest: pullObject(pull, repo), clientMutationId: (input.clientMutationId as string | null) ?? null };
      }
      pull.state = 'closed';
      pull.merged = true;
      pull.mergedAt = isoAt(store.nextSeq());
      pull.mergeCommitSha = mergeSha;
      pull.updatedSeq = store.nextSeq();
      return { __typename: 'MergePullRequestPayload', pullRequest: pullObject(pull, repo), clientMutationId: (input.clientMutationId as string | null) ?? null };
    }
    if (field === 'addComment') {
      const input = (args.input ?? {}) as Record<string, GqlValue>;
      const subjectId = typeof input.subjectId === 'string' ? input.subjectId : '';
      const body = typeof input.body === 'string' ? input.body : '';
      const decoded = store.decodeGlobalId(subjectId);
      let found: { issue: Issue; repo: Repo } | null = null;
      if (decoded?.kind === 'Issue') {
        for (const repo of store.repos.values()) {
          const issue = repo.issues.find((i) => i.id === Number(decoded.internal));
          if (issue) {
            found = { issue, repo };
            break;
          }
        }
      } else if (decoded?.kind === 'PullRequest') {
        for (const repo of store.repos.values()) {
          const pull = repo.pulls.find((p) => p.id === Number(decoded.internal));
          if (pull) {
            const issue = repo.issuesByNumber.get(pull.number);
            if (issue) found = { issue, repo };
            break;
          }
        }
      }
      if (!found) {
        ctx.errors.push({ message: 'Could not resolve to a subject with the global id provided.' });
        return { __typename: 'AddCommentPayload', commentEdge: null, clientMutationId: (input.clientMutationId as string | null) ?? null };
      }
      const comment: Comment = { id: store.nextGlobalId++, body, user: VIEWER_LOGIN, createdSeq: store.nextSeq() };
      found.issue.comments.push(comment);
      const node: GqlObject = {
        __typename: 'IssueComment',
        id: store.globalId('IssueComment', comment.id),
        databaseId: comment.id,
        body: comment.body,
        createdAt: isoAt(comment.createdSeq),
      };
      return {
        __typename: 'AddCommentPayload',
        commentEdge: { __typename: 'IssueCommentEdge', node, cursor: encodeCursor(comment.id) },
        clientMutationId: (input.clientMutationId as string | null) ?? null,
      };
    }
  }
  if (type === 'Repository') {
    const repo = parent.__repo as Repo;
    if (field === 'owner') return viewerObject();
    if (field === 'defaultBranchRef') {
      const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      if (tip === undefined) return null;
      return { __typename: 'Ref', name: repo.defaultBranch, target: { __typename: 'Commit', oid: tip }, prefix: 'refs/heads/' };
    }
    if (field === 'issue') {
      const number = typeof args.number === 'number' ? args.number : -1;
      const issue = repo.issuesByNumber.get(number);
      return issue ? issueObject(issue, repo) : null;
    }
    if (field === 'issues') {
      const first = typeof args.first === 'number' ? args.first : null;
      const after = typeof args.after === 'string' ? args.after : null;
      const states = Array.isArray(args.states) ? (args.states as string[]) : null;
      const orderBy = (args.orderBy ?? {}) as Record<string, GqlValue>;
      const direction = typeof orderBy.direction === 'string' ? orderBy.direction : 'DESC';
      let list = [...repo.issues];
      if (states !== null) {
        list = list.filter((i) => states.includes(i.state === 'open' ? 'OPEN' : 'CLOSED'));
      }
      list.sort((a, b) => {
        if (direction === 'ASC') return a.createdSeq - b.createdSeq || a.number - b.number;
        return b.createdSeq - a.createdSeq || b.number - a.number;
      });
      const ordered = list.map((i) => issueObject(i, repo));
      return connectionOf('IssueConnection', ordered, first, after);
    }
    if (field === 'pullRequest') {
      const number = typeof args.number === 'number' ? args.number : -1;
      const pull = repo.pullsByNumber.get(number);
      return pull ? pullObject(pull, repo) : null;
    }
    if (field === 'pullRequests') {
      const first = typeof args.first === 'number' ? args.first : null;
      const after = typeof args.after === 'string' ? args.after : null;
      const states = Array.isArray(args.states) ? (args.states as string[]) : null;
      let list = [...repo.pulls];
      if (states !== null) {
        list = list.filter((p) => states.includes(p.merged ? 'MERGED' : p.state === 'open' ? 'OPEN' : 'CLOSED'));
      }
      list.sort((a, b) => b.createdSeq - a.createdSeq || b.number - a.number);
      const ordered = list.map((p) => pullObject(p, repo));
      return connectionOf('PullRequestConnection', ordered, first, after);
    }
  }
  if (type === 'Issue') {
    const issue = parent.__issue as Issue;
    const repo = parent.__repo as Repo;
    if (field === 'author') return viewerObject();
    if (field === 'repository') return repositoryObject(repo);
    if (field === 'comments') {
      const first = typeof args.first === 'number' ? args.first : null;
      const after = typeof args.after === 'string' ? args.after : null;
      const nodes = issue.comments.map((c) => ({
        __typename: 'IssueComment',
        id: store.globalId('IssueComment', c.id),
        databaseId: c.id,
        body: c.body,
        createdAt: isoAt(c.createdSeq),
      }));
      const ordered = nodes.map((n, index) => ({ ...n, number: index + 1 }));
      return connectionOf('IssueConnection', ordered, first, after);
    }
  }
  if (type === 'PullRequest') {
    const pull = parent.__pull as Pull;
    const repo = parent.__repo as Repo;
    if (field === 'mergeable') return pullMergeable(repo, pull);
    if (field === 'author') return viewerObject();
    if (field === 'repository') return repositoryObject(repo);
    if (field === 'files') {
      const first = typeof args.first === 'number' ? args.first : null;
      const after = typeof args.after === 'string' ? args.after : null;
      const base = mergeBase(repo, pull.baseSha, pull.headSha);
      const baseTree = base === null ? null : parseCommit(repo.objects.get(base)?.data ?? Buffer.alloc(0)).tree;
      const headTree = parseCommit(repo.objects.get(pull.headSha)?.data ?? Buffer.alloc(0)).tree;
      const diffs = diffTrees(repo, baseTree, headTree);
      const nodes: GqlObject[] = diffs.map((d, index) => ({
        __typename: 'PullRequestFile',
        path: d.filename,
        additions: d.additions,
        deletions: d.deletions,
        changeType: d.status === 'added' ? 'ADDED' : d.status === 'removed' ? 'REMOVED' : 'MODIFIED',
        number: index + 1,
      }));
      return connectionOf('PullRequestFileConnection', nodes, first, after);
    }
  }
  if (type === 'User') {
    if (field === 'id' || field === 'databaseId' || field === 'login' || field === 'name' || field === 'email' || field === 'url' || field === 'avatarUrl') {
      return parent[field] ?? null;
    }
  }
  if (type === '__Type') {
    if (field === 'fields') {
      const includeDeprecated = args.includeDeprecated === true;
      const fields = (parent.fields ?? null) as GqlObject[] | null;
      if (fields === null) return null;
      return includeDeprecated ? fields : fields.filter((f) => f.isDeprecated !== true);
    }
    if (field === 'enumValues') {
      const includeDeprecated = args.includeDeprecated === true;
      const values = (parent.enumValues ?? null) as GqlObject[] | null;
      if (values === null) return null;
      return includeDeprecated ? values : values.filter((v) => v.isDeprecated !== true);
    }
    if (field === 'ofType' || field === 'inputFields' || field === 'interfaces' || field === 'possibleTypes') {
      return parent[field] ?? null;
    }
  }
  // Plain property access for the remaining scalar fields.
  if (field in parent && typeof parent[field] !== 'function') return parent[field] as unknown;
  return undefined;
}

function executeSelections(
  parent: GqlObject,
  selections: readonly GqlSelection[],
  variables: Record<string, GqlValue>,
  defaults: Record<string, { type: string; defaultValue?: GqlValue }>,
  ctx: GqlContext,
): { [key: string]: GqlValue } {
  const out: { [key: string]: GqlValue } = {};
  for (const selection of selections) {
    if (selection.kind === 'named') {
      const fragment = ctx.document.fragments.get(selection.name);
      if (fragment) Object.assign(out, executeSelections(parent, fragment.selections, variables, defaults, ctx));
      continue;
    }
    if (selection.kind === 'fragment') {
      if (selection.typeCondition !== null && selection.typeCondition !== parent.__typename) continue;
      Object.assign(out, executeSelections(parent, selection.selections, variables, defaults, ctx));
      continue;
    }
    const key = selection.alias ?? selection.name;
    if (selection.name === '__typename') {
      out[key] = parent.__typename;
      continue;
    }
    const resolvedArgs: Record<string, GqlValue> = {};
    for (const [name, value] of Object.entries(selection.args)) {
      resolvedArgs[name] = resolveVariables(value, variables, defaults);
    }
    const value = resolveField(parent, selection.name, resolvedArgs, ctx);
    if (value === undefined) {
      ctx.errors.push({ message: `Cannot query field "${selection.name}" on type "${parent.__typename}".` });
      out[key] = null;
      continue;
    }
    out[key] = executeValue(value, selection.selections, variables, defaults, ctx);
  }
  return out;
}

function executeValue(
  value: unknown,
  selections: readonly GqlSelection[],
  variables: Record<string, GqlValue>,
  defaults: Record<string, { type: string; defaultValue?: GqlValue }>,
  ctx: GqlContext,
): GqlValue {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) {
    return value.map((entry) => executeValue(entry, selections, variables, defaults, ctx));
  }
  if (typeof value === 'object' && '__typename' in (value as Record<string, unknown>)) {
    const object = value as GqlObject;
    const cleaned: GqlObject = { __typename: object.__typename };
    for (const [key, entry] of Object.entries(object)) {
      if (key.startsWith('__') && key !== '__typename') continue;
      cleaned[key] = entry;
    }
    if (selections.length === 0) return cleaned as unknown as GqlValue;
    return executeSelections(object, selections, variables, defaults, ctx);
  }
  if (typeof value === 'object') {
    // A plain object (e.g. an edge): resolve its fields from the selection set.
    const object = value as GqlObject;
    if (selections.length === 0) return value as GqlValue;
    const withType: GqlObject = { ...object, __typename: object.__typename ?? 'Object' };
    return executeSelections(withType, selections, variables, defaults, ctx);
  }
  return value as GqlValue;
}

function executeOperation(operation: GqlOperation, variables: Record<string, GqlValue>, document: GqlDocument): { data: { [key: string]: GqlValue }; errors?: { message: string }[] } {
  const ctx: GqlContext = { errors: [], document };
  const root: GqlObject = { __typename: operation.kind === 'mutation' ? 'Mutation' : 'Query' };
  const data = executeSelections(root, operation.selections, variables, operation.variables, ctx);
  const result: { data: { [key: string]: GqlValue }; errors?: { message: string }[] } = { data };
  if (ctx.errors.length > 0) result.errors = ctx.errors;
  return result;
}

function handleGraphQL(ctx: Ctx): boolean {
  const { req, res } = ctx;
  if (!ctx.authed) {
    sendError(res, 401, 'Requires authentication');
    return true;
  }
  let body: unknown;
  try {
    body = JSON.parse(ctx.body.toString('utf8'));
  } catch {
    sendError(res, 400, 'Invalid JSON body');
    return true;
  }
  const requests: unknown[] = Array.isArray(body) ? body : [body];
  const isBatch = Array.isArray(body);
  const results: unknown[] = [];
  for (const request of requests) {
    if (request === null || typeof request !== 'object') {
      results.push({ errors: [{ message: 'Invalid GraphQL request' }] });
      continue;
    }
    const { query, variables, operationName } = request as { query?: unknown; variables?: unknown; operationName?: unknown };
    if (typeof query !== 'string' || query.trim() === '') {
      results.push({ errors: [{ message: 'Query is required' }] });
      continue;
    }
    let document: GqlDocument;
    try {
      document = new GqlParser(query).parseDocument();
    } catch (error) {
      results.push({ errors: [{ message: `Syntax Error: ${safeText(error instanceof Error ? error.message : error)}` }] });
      continue;
    }
    let operation = document.operations[0];
    if (typeof operationName === 'string') {
      operation = document.operations.find((op) => op.name === operationName) ?? operation;
    }
    if (!operation) {
      results.push({ errors: [{ message: 'No operation found' }] });
      continue;
    }
    const vars = variables !== null && typeof variables === 'object' && !Array.isArray(variables)
      ? (variables as Record<string, GqlValue>)
      : {};
    results.push(executeOperation(operation, vars, document));
  }
  sendJson(res, 200, isBatch ? results : results[0]);
  return true;
}

// ---------------------------------------------------------------------------------------------
// MCP (Model Context Protocol, streamable HTTP)
// ---------------------------------------------------------------------------------------------

interface McpTool {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Readonly<Record<string, { type: string; description: string }>>;
    required: readonly string[];
  };
}

const MCP_TOOLS: readonly McpTool[] = Object.freeze([
  Object.freeze({
    name: 'create_repo',
    description: 'Create a new repository owned by the authenticated user.',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        name: { type: 'string', description: 'The name of the repository.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
        owner: { type: 'string', description: 'The owner of the repository (defaults to the authenticated user).' },
      }),
      required: Object.freeze(['name']),
    }),
  }),
  Object.freeze({
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
        full_name: { type: 'string', description: 'The full name of the repository (owner/repo).' },
      }),
      required: Object.freeze(['owner', 'repo']),
    }),
  }),
  Object.freeze({
    name: 'create_issue',
    description: 'Create a new issue in a repository.',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
        full_name: { type: 'string', description: 'The full name of the repository (owner/repo).' },
        title: { type: 'string', description: 'The title of the issue.' },
        body: { type: 'string', description: 'The body of the issue.' },
      }),
      required: Object.freeze(['owner', 'repo', 'title']),
    }),
  }),
  Object.freeze({
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
        full_name: { type: 'string', description: 'The full name of the repository (owner/repo).' },
        state: { type: 'string', description: 'Filter by state: open, closed, or all.' },
      }),
      required: Object.freeze(['owner', 'repo']),
    }),
  }),
  Object.freeze({
    name: 'create_pull_request',
    description: 'Create a new pull request in a repository.',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
        full_name: { type: 'string', description: 'The full name of the repository (owner/repo).' },
        title: { type: 'string', description: 'The title of the pull request.' },
        head: { type: 'string', description: 'The name of the branch where the changes are implemented.' },
        base: { type: 'string', description: 'The name of the branch the changes are pulled into.' },
        body: { type: 'string', description: 'The body of the pull request.' },
      }),
      required: Object.freeze(['owner', 'repo', 'title', 'head', 'base']),
    }),
  }),
  Object.freeze({
    name: 'merge_pull_request',
    description: 'Merge a pull request in a repository using a squash commit.',
    inputSchema: Object.freeze({
      type: 'object',
      properties: Object.freeze({
        owner: { type: 'string', description: 'The owner of the repository.' },
        repo: { type: 'string', description: 'The name of the repository.' },
        full_name: { type: 'string', description: 'The full name of the repository (owner/repo).' },
        pull_number: { type: 'integer', description: 'The number of the pull request to merge.' },
      }),
      required: Object.freeze(['owner', 'repo', 'pull_number']),
    }),
  }),
]);

const SERVER_INFO = Object.freeze({ name: 'makefun-git-forge', version: '1.0.0' });

/** Split `owner`/`repo` (or `full_name`) arguments into a repo lookup. */
function mcpRepo(args: Record<string, unknown>): Repo | null {
  let owner = typeof args.owner === 'string' ? args.owner : '';
  let repoName = typeof args.repo === 'string' ? args.repo : '';
  if ((owner === '' || repoName === '') && typeof args.full_name === 'string') {
    const parts = (args.full_name as string).split('/');
    if (parts.length === 2) {
      owner = owner === '' ? (parts[0] as string) : owner;
      repoName = repoName === '' ? (parts[1] as string) : repoName;
    }
  }
  if (owner === '' || repoName === '') return null;
  const repo = store.getRepo(repoName);
  return repo && repo.owner === owner ? repo : null;
}

function mcpToolResult(obj: Record<string, unknown>): Record<string, unknown> {
  const text = JSON.stringify(obj);
  return { content: [{ type: 'text', text }], structuredContent: obj };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpMissingArg(name: string): { code: number; message: string } {
  return { code: -32602, message: `Invalid params: ${name} is required` };
}

function callMcpTool(name: string, args: Record<string, unknown>): { result?: Record<string, unknown>; error?: { code: number; message: string } } {
  if (name === 'create_repo') {
    const repoName = typeof args.name === 'string' ? args.name.trim() : '';
    if (repoName === '') return { error: mcpMissingArg('name') };
    if (store.getRepo(repoName)) {
      return { result: mcpToolError(`Repository ${repoName} already exists`) };
    }
    const repo = store.createRepo(
      repoName,
      typeof args.description === 'string' ? args.description : '',
      args.private === true,
    );
    return { result: mcpToolResult({ id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}`, private: repo.private, description: repo.description, default_branch: repo.defaultBranch, owner: { login: repo.owner } }) };
  }
  if (name === 'get_repo') {
    const repo = mcpRepo(args);
    if (!repo) return { result: mcpToolError('Repository not found') };
    return { result: mcpToolResult({ id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}`, private: repo.private, description: repo.description, default_branch: repo.defaultBranch, owner: { login: repo.owner } }) };
  }
  if (name === 'create_issue') {
    const repo = mcpRepo(args);
    if (!repo) return { result: mcpToolError('Repository not found') };
    const title = typeof args.title === 'string' ? args.title : '';
    if (title === '') return { error: mcpMissingArg('title') };
    const seq = store.nextSeq();
    const issue: Issue = {
      id: store.nextGlobalId++,
      number: repo.nextNumber++,
      title,
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      labels: [],
      comments: [],
      createdSeq: seq,
      updatedSeq: seq,
    };
    repo.issues.push(issue);
    repo.issuesByNumber.set(issue.number, issue);
    return { result: mcpToolResult({ id: issue.id, number: issue.number, title: issue.title, body: issue.body, state: issue.state, repository: `${repo.owner}/${repo.name}` }) };
  }
  if (name === 'list_issues') {
    const repo = mcpRepo(args);
    if (!repo) return { result: mcpToolError('Repository not found') };
    const state = typeof args.state === 'string' ? args.state : 'open';
    let list = [...repo.issues];
    if (state === 'open') list = list.filter((i) => i.state === 'open');
    else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
    list.sort((a, b) => b.createdSeq - a.createdSeq);
    const issues = list.map((i) => ({ id: i.id, number: i.number, title: i.title, body: i.body, state: i.state }));
    return { result: mcpToolResult({ issues }) };
  }
  if (name === 'create_pull_request') {
    const repo = mcpRepo(args);
    if (!repo) return { result: mcpToolError('Repository not found') };
    const title = typeof args.title === 'string' ? args.title : '';
    const head = typeof args.head === 'string' ? args.head : '';
    const base = typeof args.base === 'string' ? args.base : '';
    if (title === '') return { error: mcpMissingArg('title') };
    if (head === '') return { error: mcpMissingArg('head') };
    if (base === '') return { error: mcpMissingArg('base') };
    const headSha = resolveRef(repo, head);
    const baseSha = resolveRef(repo, base);
    if (headSha === null || baseSha === null) {
      return { result: mcpToolError('Validation Failed: head or base branch does not exist') };
    }
    const duplicate = repo.pulls.find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
    if (duplicate) {
      return { result: mcpToolError('A pull request already exists for this branch') };
    }
    const seq = store.nextSeq();
    const pull: Pull = {
      id: store.nextGlobalId++,
      number: repo.nextNumber++,
      title,
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      headRef: head,
      baseRef: base,
      headSha,
      baseSha,
      createdSeq: seq,
      updatedSeq: seq,
    };
    repo.pulls.push(pull);
    repo.pullsByNumber.set(pull.number, pull);
    return { result: mcpToolResult({ id: pull.id, number: pull.number, title: pull.title, body: pull.body, state: pull.state, head: { ref: head, sha: headSha }, base: { ref: base, sha: baseSha }, repository: `${repo.owner}/${repo.name}` }) };
  }
  if (name === 'merge_pull_request') {
    const repo = mcpRepo(args);
    if (!repo) return { result: mcpToolError('Repository not found') };
    const pullNumber = typeof args.pull_number === 'number' ? args.pull_number : Number(args.pull_number);
    if (!Number.isInteger(pullNumber) || pullNumber <= 0) return { error: mcpMissingArg('pull_number') };
    const pull = repo.pullsByNumber.get(pullNumber);
    if (!pull) return { result: mcpToolError('Pull request not found') };
    if (pull.state !== 'open') return { result: mcpToolError('Pull request is already closed') };
    const mergeSha = squashMerge(repo, pull);
    if (mergeSha === null) return { result: mcpToolError('Merge conflict') };
    pull.state = 'closed';
    pull.merged = true;
    pull.mergedAt = isoAt(store.nextSeq());
    pull.mergeCommitSha = mergeSha;
    pull.updatedSeq = store.nextSeq();
    return { result: mcpToolResult({ number: pull.number, merged: true, sha: mergeSha, state: 'closed', merge_commit_sha: mergeSha, repository: `${repo.owner}/${repo.name}` }) };
  }
  return { error: { code: -32602, message: `Unknown tool: ${name}` } };
}

function handleMcp(ctx: Ctx): boolean {
  const { res } = ctx;
  if (!ctx.authed) {
    sendError(res, 401, 'Requires authentication');
    return true;
  }
  let body: unknown;
  try {
    body = ctx.body.length === 0 ? null : JSON.parse(ctx.body.toString('utf8'));
  } catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return true;
  }
  const requests = Array.isArray(body) ? body : [body];
  const responses: unknown[] = [];
  let hasResponse = false;
  for (const request of requests) {
    if (request === null || typeof request !== 'object' || Array.isArray(request)) {
      responses.push({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
      hasResponse = true;
      continue;
    }
    const { method, params, id } = request as { method?: unknown; params?: unknown; id?: unknown };
    const isNotification = id === undefined;
    if (typeof method !== 'string') {
      if (!isNotification) {
        responses.push({ jsonrpc: '2.0', id: id ?? null, error: { code: -32600, message: 'Invalid Request' } });
        hasResponse = true;
      }
      continue;
    }
    if (isNotification) {
      // Notifications (e.g. notifications/initialized) are acknowledged with an empty 202.
      continue;
    }
    hasResponse = true;
    const paramsObject = params !== null && typeof params === 'object' && !Array.isArray(params)
      ? (params as Record<string, unknown>)
      : {};
    if (method === 'server/discover') {
      responses.push({
        jsonrpc: '2.0',
        id,
        result: {
          supportedVersions: ['2026-07-28', '2025-11-25'],
          capabilities: { tools: {} },
          serverInfo: SERVER_INFO,
          _meta: { 'io.modelcontextprotocol/serverInfo': SERVER_INFO },
        },
      });
      continue;
    }
    if (method === 'initialize') {
      responses.push({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: typeof paramsObject.protocolVersion === 'string' ? paramsObject.protocolVersion : '2026-07-28',
          capabilities: { tools: {} },
          serverInfo: SERVER_INFO,
        },
      });
      continue;
    }
    if (method === 'ping') {
      responses.push({ jsonrpc: '2.0', id, result: {} });
      continue;
    }
    if (method === 'tools/list') {
      responses.push({ jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } });
      continue;
    }
    if (method === 'tools/call') {
      const toolName = typeof paramsObject.name === 'string' ? paramsObject.name : '';
      const toolArgs = paramsObject.arguments !== null && typeof paramsObject.arguments === 'object' && !Array.isArray(paramsObject.arguments)
        ? (paramsObject.arguments as Record<string, unknown>)
        : {};
      const outcome = callMcpTool(toolName, toolArgs);
      if (outcome.error) {
        responses.push({ jsonrpc: '2.0', id, error: outcome.error });
      } else {
        responses.push({ jsonrpc: '2.0', id, result: outcome.result });
      }
      continue;
    }
    responses.push({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
  }
  if (!hasResponse) {
    res.writeHead(202, { 'x-github-request-id': nextRequestId() });
    res.end();
    return true;
  }
  sendJson(res, 200, Array.isArray(body) ? responses : responses[0]);
  return true;
}

// ---------------------------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------------------------

export function createApp(): Server {
  const server = createServer((req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
        const path = decodeURIComponent(url.pathname);
        const segments = path.split('/').filter((s) => s !== '');
        const body = (req.method === 'GET' || req.method === 'HEAD') ? Buffer.alloc(0) : await readBody(req);
        const ctx: Ctx = {
          req,
          res,
          path,
          segments,
          query: url.searchParams,
          body,
          json: null,
          authed: authed(req),
        };
        const method = req.method ?? 'GET';
        if (path === '/healthz' && method === 'GET') {
          sendJson(res, 200, { ok: true });
          return;
        }
        if (segments[0] === 'api' && segments[1] === 'v3') {
          if (handleRest(ctx)) return;
        } else if (path === '/api/graphql' && method === 'POST') {
          if (handleGraphQL(ctx)) return;
        } else if (path === '/mcp' && method === 'POST') {
          if (handleMcp(ctx)) return;
        } else if (segments.length >= 3 && (segments[1] ?? '').endsWith('.git')) {
          if (handleGit(ctx)) return;
        }
        sendError(res, 404, 'Not Found');
      } catch (error) {
        if (!res.headersSent) {
          sendError(res, 500, `Internal error: ${safeText(error instanceof Error ? error.message : error)}`);
        } else {
          res.end();
        }
      }
    })();
  });
  return server;
}
