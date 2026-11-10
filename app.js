/* GitVault — photo & video backup to a GitHub repository.
 * Runs entirely in the browser; talks directly to the GitHub REST API.
 *
 * Repository layout:
 *   media/YYYY/MM/YYYYMMDD-HHMMSS_<name>              original file (<= 45 MB)
 *   media/YYYY/MM/YYYYMMDD-HHMMSS_<name>.parts/part-000 ... large files split into 45 MB parts
 *   thumbs/<media path>.jpg                            small preview generated on upload
 */

const API = 'https://api.github.com';
const MEDIA_DIR = 'media';
const THUMB_DIR = 'thumbs';
const CHUNK = 45 * 1024 * 1024;          // stay well under GitHub's 50 MB warning / 100 MB hard limit
const MAX_FILE = 2 * 1024 * 1024 * 1024; // browser memory is the practical limit
const BATCH_FILES = 10;
const BATCH_BYTES = 150 * 1024 * 1024;
const THUMB_PX = 360;
const STORE_KEY = 'gitvault:v2';
const AUTO_LOCK_MS = 10 * 60 * 1000;   // lock after 10 minutes without interaction
const PBKDF2_ITER = 310000;

const IMAGE_TYPES = {
  jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp',
  heic: 'image/heic', heif: 'image/heif', avif: 'image/avif', bmp: 'image/bmp', tif: 'image/tiff',
  tiff: 'image/tiff', dng: 'image/x-adobe-dng',
};
const VIDEO_TYPES = {
  mp4: 'video/mp4', m4v: 'video/x-m4v', mov: 'video/quicktime', webm: 'video/webm',
  mkv: 'video/x-matroska', avi: 'video/x-msvideo', '3gp': 'video/3gpp',
};

const $ = (s, r = document) => r.querySelector(s);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const pad = n => String(n).padStart(2, '0');

// ---------------------------------------------------------------- state
const S = {
  cfg: null,          // { token, owner, repo } — token only ever in memory once unlocked
  user: null,
  repoInfo: null,
  branch: 'main',
  items: [],          // sorted newest first
  byPath: new Map(),
  thumbs: new Map(),  // media path -> thumbnail blob sha
  shas: new Set(),    // content keys already in the library (dedupe)
  pending: new Set(), // content keys currently uploading
  reserved: new Set(),// paths taken or being uploaded
  filter: 'all',
  view: [],
  selecting: false,
  selected: new Set(),
  viewIndex: -1,
  uploads: 0,
};

// ---------------------------------------------------------------- storage (token encrypted with the app password)
// Saved on the device: { owner, repo, sealed: { salt, iv, data, iter } }.
// The GitHub token is encrypted with AES-GCM using a key derived from the app password (PBKDF2-SHA256),
// so without the password neither the album nor the token can be reached from this device.
const store = {
  get() {
    try { return JSON.parse(localStorage.getItem(STORE_KEY) || 'null'); } catch { return null; }
  },
  set(saved) {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(saved)); } catch { /* private mode: works until the page closes */ }
  },
  clear() {
    try { localStorage.removeItem(STORE_KEY); localStorage.removeItem('gitvault:v1'); sessionStorage.removeItem('gitvault:v1'); } catch {}
  },
};

const te = new TextEncoder();
const b64e = u8 => { let s = ''; for (const b of u8) s += String.fromCharCode(b); return btoa(s); };
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const utf8b64 = str => b64e(te.encode(str));

async function deriveKey(password, salt, iter) {
  const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function sealToken(token, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, PBKDF2_ITER);
  const data = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(token)));
  return { salt: b64e(salt), iv: b64e(iv), data: b64e(data), iter: PBKDF2_ITER };
}
async function openToken(sealed, password) {
  const key = await deriveKey(password, b64d(sealed.salt), sealed.iter || PBKDF2_ITER);
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(sealed.iv) }, key, b64d(sealed.data));
    return new TextDecoder().decode(plain);
  } catch {
    throw new Error('Wrong password.');
  }
}
async function saveConfig(cfg, password) {
  store.set({ owner: cfg.owner, repo: cfg.repo, sealed: await sealToken(cfg.token, password) });
}

// ---------------------------------------------------------------- GitHub API
class GHError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const R = () => `/repos/${S.cfg.owner}/${S.cfg.repo}`;

function headers(extra = {}) {
  return {
    Authorization: `Bearer ${S.cfg.token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    ...extra,
  };
}

function explain(status, message, rateLimited) {
  if (status === 401) return 'GitHub rejected the token (it may be expired or mistyped).';
  if (rateLimited) return 'GitHub API rate limit reached — wait a few minutes and try again.';
  if (status === 403 && /Resource not accessible/i.test(message)) return 'The token lacks permission for this action (needs Contents: Read and write).';
  return message || `GitHub error ${status}`;
}

async function gh(path, { method = 'GET', body, accept, raw = false } = {}) {
  let res;
  for (let attempt = 0; ; attempt++) {
    try {
      res = await fetch(API + path, {
        method,
        headers: headers({ ...(accept ? { Accept: accept } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }),
        body: body ? JSON.stringify(body) : undefined,
        cache: 'no-store',
      });
    } catch (e) {
      if (attempt < 2) { await sleep(1000 * (attempt + 1)); continue; }
      throw new Error('Network error — are you online?');
    }
    if (res.status >= 500 && attempt < 2) { await sleep(1000 * (attempt + 1)); continue; }
    break;
  }
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).message || msg; } catch {}
    throw new GHError(res.status, explain(res.status, msg, res.headers.get('x-ratelimit-remaining') === '0'));
  }
  if (raw) return res;
  if (res.status === 204) return null;
  return res.json();
}

/** Upload one git blob with progress (fetch has no upload progress, XHR does). */
function postBlobOnce(b64, onProgress) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open('POST', `${API}${R()}/git/blobs`);
    for (const [k, v] of Object.entries(headers({ 'Content-Type': 'application/json' }))) x.setRequestHeader(k, v);
    x.responseType = 'json';
    if (onProgress) x.upload.onprogress = e => e.lengthComputable && onProgress(e.loaded / e.total);
    x.onload = () => {
      if (x.status >= 200 && x.status < 300) resolve(x.response);
      else reject(new GHError(x.status, explain(x.status, x.response?.message, x.getResponseHeader('x-ratelimit-remaining') === '0')));
    };
    x.onerror = () => reject(new GHError(0, 'Network error during upload'));
    x.send(JSON.stringify({ content: b64, encoding: 'base64' }));
  });
}
async function postBlob(b64, onProgress) {
  for (let attempt = 0; ; attempt++) {
    try { return await postBlobOnce(b64, onProgress); }
    catch (e) {
      if (attempt < 3 && (e.status === 0 || e.status >= 500)) { await sleep(2000 * 2 ** attempt); continue; }
      throw e;
    }
  }
}

async function getHead() {
  const ref = await gh(`${R()}/git/ref/heads/${S.branch}`);
  const commit = await gh(`${R()}/git/commits/${ref.object.sha}`);
  return { commitSha: ref.object.sha, treeSha: commit.tree.sha };
}

/** Apply tree changes as one commit on top of the current branch head (retries on races). */
async function commitEntries(entries, message) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const head = await getHead();
    const tree = await gh(`${R()}/git/trees`, { method: 'POST', body: { base_tree: head.treeSha, tree: entries } });
    const commit = await gh(`${R()}/git/commits`, { method: 'POST', body: { message, tree: tree.sha, parents: [head.commitSha] } });
    try {
      await gh(`${R()}/git/refs/heads/${S.branch}`, { method: 'PATCH', body: { sha: commit.sha, force: false } });
      return commit.sha;
    } catch (e) {
      if (e.status !== 422 && e.status !== 409) throw e;
      await sleep(700 * (attempt + 1)); // someone else committed first; rebuild on the new head
    }
  }
  throw new Error('The repository kept changing while saving. Please try again.');
}

const REPO_README = `# Photo & video backup

This repository is managed by GitVault.

- \`media/YYYY/MM/\` — original photos and videos, named by capture date.
  Files larger than 45 MB are stored as \`<name>.parts/part-000\`, \`part-001\`, …
  (join them in order to get the original file back, e.g. \`cat part-* > video.mov\`).
- \`thumbs/\` — small preview images used by the gallery.
`;

async function ensureInitialized() {
  for (let attempt = 0; attempt < 4; attempt++) {
    try { await getHead(); return; }
    catch (e) { if (e.status !== 404 && e.status !== 409) throw e; }
    try {
      // Empty repositories have no branch yet; the Git data API needs one, so make a first commit.
      await gh(`${R()}/contents/README.md`, {
        method: 'PUT',
        body: { message: 'Initialize photo backup', content: utf8b64(REPO_README), branch: S.branch },
      });
      return;
    } catch (e) {
      if (e.status === 403 || e.status === 404) {
        throw new Error(`GitHub didn't let the app add the first file to the empty repository ${S.cfg.owner}/${S.cfg.repo} (${e.message}). ` +
          'Fix: on github.com open that repository, tap "Add a README" (or "creating a new file"), commit it, then tap Connect again.');
      }
      if (e.status !== 422 && e.status !== 409) throw e; // README exists but ref not visible yet — retry
      await sleep(1500);
    }
  }
  await getHead();
}

async function connect(cfg, { create = false } = {}) {
  S.cfg = cfg;
  const stepErr = (what, e) => Object.assign(new Error(`While ${what}: ${e.message}`), { status: e.status });
  try {
    S.user = await gh('/user');
  } catch (e) {
    if (e.status === 401) throw e;
    S.user = null; // only needed for display / creating repos
  }
  let repo;
  try {
    repo = await gh(R());
  } catch (e) {
    if (e.status !== 404) throw stepErr('opening the repository', e);
    if (!S.user) throw new Error(`Repository ${cfg.owner}/${cfg.repo} was not found, or this token can't access it.`);
    if (!create) throw new Error(`Repository ${cfg.owner}/${cfg.repo} was not found, or this token can't access it.`);
    const body = { name: cfg.repo, private: true, auto_init: true, description: 'Photo & video backup (GitVault)' };
    const mine = cfg.owner.toLowerCase() === S.user.login.toLowerCase();
    repo = await gh(mine ? '/user/repos' : `/orgs/${cfg.owner}/repos`, { method: 'POST', body });
    cfg.owner = repo.owner.login;
    cfg.repo = repo.name;
  }
  if (repo.permissions && repo.permissions.push === false) throw new Error('You only have read access to this repository.');
  S.repoInfo = repo;
  S.branch = repo.default_branch || 'main';
  try {
    await ensureInitialized();
  } catch (e) {
    throw /^GitHub didn't let/.test(e.message) ? e : stepErr('preparing the repository', e);
  }
}

// ---------------------------------------------------------------- library model
function extOf(name) {
  const m = /\.([a-z0-9]+)$/i.exec(name);
  return m ? m[1].toLowerCase() : '';
}
function kindOfName(name) {
  const e = extOf(name);
  if (IMAGE_TYPES[e]) return 'image';
  if (VIDEO_TYPES[e]) return 'video';
  return null;
}
function kindOfFile(f) {
  if (f.type.startsWith('image/')) return 'image';
  if (f.type.startsWith('video/')) return 'video';
  return kindOfName(f.name);
}
function mimeOf(name) {
  const e = extOf(name);
  return IMAGE_TYPES[e] || VIDEO_TYPES[e] || 'application/octet-stream';
}
const thumbPath = p => `${THUMB_DIR}/${p}.jpg`;

function makeItem(path, parts) {
  const name = path.split('/').pop();
  let date = null;
  const m = /^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})_/.exec(name);
  if (m) date = new Date(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  else {
    const d = /\/(\d{4})\/(\d{2})\//.exec(path);
    date = d ? new Date(+d[1], d[2] - 1, 1) : new Date(0);
  }
  return {
    path,
    name,
    displayName: m ? name.slice(16) : name,
    kind: kindOfName(name),
    mime: mimeOf(name),
    date,
    parts, // [{ sha, size, path }]
    size: parts.reduce((s, p) => s + p.size, 0),
    key: parts[0].sha,
  };
}

function sortItems() {
  S.items.sort((a, b) => b.date - a.date || (a.name < b.name ? 1 : -1));
  S.byPath = new Map(S.items.map(i => [i.path, i]));
  S.shas = new Set(S.items.map(i => i.key));
}

async function loadLibrary() {
  const btn = $('#btn-refresh');
  btn.classList.add('spin');
  if (!S.items.length) $('#loading').hidden = false;
  try {
    const head = await getHead();
    const tree = await gh(`${R()}/git/trees/${head.treeSha}?recursive=1`);
    const singles = [];
    const chunked = new Map();
    S.thumbs = new Map();
    for (const e of tree.tree) {
      if (e.type !== 'blob') continue;
      if (e.path.startsWith(THUMB_DIR + '/') && e.path.endsWith('.jpg')) {
        S.thumbs.set(e.path.slice(THUMB_DIR.length + 1, -4), e.sha);
        continue;
      }
      if (!e.path.startsWith(MEDIA_DIR + '/')) continue;
      const pm = /^(.*)\.parts\/part-(\d+)$/.exec(e.path);
      if (pm) {
        if (!kindOfName(pm[1])) continue;
        if (!chunked.has(pm[1])) chunked.set(pm[1], []);
        chunked.get(pm[1]).push({ idx: +pm[2], sha: e.sha, size: e.size, path: e.path });
      } else if (kindOfName(e.path)) {
        singles.push(makeItem(e.path, [{ sha: e.sha, size: e.size, path: e.path }]));
      }
    }
    for (const [path, parts] of chunked) {
      parts.sort((a, b) => a.idx - b.idx);
      singles.push(makeItem(path, parts));
    }
    S.items = singles;
    sortItems();
    for (const p of S.byPath.keys()) S.reserved.add(p);
    S.truncated = !!tree.truncated;
    S.repoInfo = await gh(R()).catch(() => S.repoInfo);
    renderGallery();
  } finally {
    btn.classList.remove('spin');
    $('#loading').hidden = true;
  }
}

// ---------------------------------------------------------------- fetching media
function limiter(n) {
  let active = 0;
  const q = [];
  const next = () => {
    if (active >= n || !q.length) return;
    active++;
    const { fn, res, rej } = q.shift();
    fn().then(res, rej).finally(() => { active--; next(); });
  };
  return fn => new Promise((res, rej) => { q.push({ fn, res, rej }); next(); });
}
const fetchLimit = limiter(6);

async function fetchBlob(sha) {
  const res = await fetchLimit(() => gh(`${R()}/git/blobs/${sha}`, { accept: 'application/vnd.github.raw+json', raw: true }));
  return res.blob();
}

// Thumbnails: blob shas are immutable, so cache them forever (Cache Storage) and in memory.
const thumbURLs = new Map();
function thumbURL(sha, mime) {
  if (thumbURLs.has(sha)) return thumbURLs.get(sha);
  const p = (async () => {
    const key = `https://gitvault.invalid/blob/${sha}`;
    let cache = null, blob = null;
    try { cache = await caches.open('gitvault-thumbs-v1'); const hit = await cache.match(key); if (hit) blob = await hit.blob(); } catch {}
    if (!blob) {
      blob = await fetchBlob(sha);
      if (cache) cache.put(key, new Response(blob)).catch(() => {});
    }
    return URL.createObjectURL(new Blob([blob], { type: mime }));
  })();
  thumbURLs.set(sha, p);
  p.catch(() => thumbURLs.delete(sha));
  return p;
}

// Full-size media: keep only the last few in memory (videos can be large).
const fullCache = new Map(); // path -> Promise<{ blob, url }>
function fullMedia(item, onProgress) {
  if (fullCache.has(item.path)) {
    const p = fullCache.get(item.path);
    fullCache.delete(item.path);
    fullCache.set(item.path, p); // bump to most-recent
    return p;
  }
  const p = (async () => {
    const blobs = [];
    for (let i = 0; i < item.parts.length; i++) {
      onProgress?.(i, item.parts.length);
      blobs.push(await fetchBlob(item.parts[i].sha));
    }
    const blob = new Blob(blobs, { type: item.mime });
    return { blob, url: URL.createObjectURL(blob) };
  })();
  fullCache.set(item.path, p);
  p.catch(() => fullCache.delete(item.path));
  while (fullCache.size > 4) {
    const [oldKey, old] = fullCache.entries().next().value;
    fullCache.delete(oldKey);
    old.then(v => URL.revokeObjectURL(v.url), () => {});
  }
  return p;
}

// ---------------------------------------------------------------- metadata: capture dates
/** Find EXIF "DateTimeOriginal" in JPEG or HEIC by scanning for the Exif header. */
async function exifDate(file) {
  const bytes = new Uint8Array(await file.slice(0, 1024 * 1024).arrayBuffer());
  const v = new DataView(bytes.buffer);
  for (let i = 0; i < bytes.length - 14; i++) {
    // "Exif\0\0" followed by "II" or "MM"
    if (bytes[i] === 0x45 && bytes[i + 1] === 0x78 && bytes[i + 2] === 0x69 && bytes[i + 3] === 0x66 &&
        bytes[i + 4] === 0 && bytes[i + 5] === 0 &&
        ((bytes[i + 6] === 0x49 && bytes[i + 7] === 0x49) || (bytes[i + 6] === 0x4d && bytes[i + 7] === 0x4d))) {
      try { const d = parseTiffDate(v, i + 6); if (d) return d; } catch {}
    }
  }
  return null;
}
function parseTiffDate(v, start) {
  const le = v.getUint16(start) === 0x4949;
  const end = v.byteLength;
  const u16 = o => v.getUint16(start + o, le);
  const u32 = o => v.getUint32(start + o, le);
  const str = (o, n) => {
    let s = '';
    for (let i = 0; i < n - 1 && start + o + i < end; i++) s += String.fromCharCode(v.getUint8(start + o + i));
    return s;
  };
  const readIFD = (off, want) => {
    const out = {};
    if (start + off + 2 > end) return out;
    const n = u16(off);
    for (let i = 0; i < n; i++) {
      const e = off + 2 + i * 12;
      if (start + e + 12 > end) break;
      const tag = u16(e);
      if (!want.includes(tag)) continue;
      const type = u16(e + 2), count = u32(e + 4);
      out[tag] = type === 2 ? str(count > 4 ? u32(e + 8) : e + 8, count) : u32(e + 8);
    }
    return out;
  };
  const ifd0 = readIFD(u32(4), [0x0132, 0x8769]);
  let s = null;
  if (ifd0[0x8769]) {
    const ex = readIFD(ifd0[0x8769], [0x9003, 0x9004]);
    s = ex[0x9003] || ex[0x9004];
  }
  s = s || ifd0[0x0132];
  const m = s && /^(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})/.exec(s);
  if (!m || +m[1] < 1980) return null;
  const d = new Date(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  return isNaN(d) ? null : d;
}

/** Read the creation time of a MOV/MP4 file from its 'mvhd' box. */
async function movieDate(file) {
  const four = (dv, o) => String.fromCharCode(dv.getUint8(o), dv.getUint8(o + 1), dv.getUint8(o + 2), dv.getUint8(o + 3));
  let off = 0;
  for (let guard = 0; off + 8 <= file.size && guard < 64; guard++) {
    const h = new DataView(await file.slice(off, off + 16).arrayBuffer());
    let size = h.getUint32(0);
    const type = four(h, 4);
    let hdr = 8;
    if (size === 1) { size = Number(h.getBigUint64(8)); hdr = 16; }
    else if (size === 0) size = file.size - off;
    if (size < hdr) return null;
    if (type === 'moov') {
      const dv = new DataView(await file.slice(off + hdr, off + Math.min(size, 32 * 1024 * 1024)).arrayBuffer());
      for (let p = 0; p + 20 <= dv.byteLength;) {
        const s = dv.getUint32(p);
        if (four(dv, p + 4) === 'mvhd') {
          const ver = dv.getUint8(p + 8);
          const secs = ver === 1 ? Number(dv.getBigUint64(p + 12)) : dv.getUint32(p + 12);
          if (!secs) return null;
          const d = new Date((secs - 2082844800) * 1000); // QuickTime epoch is 1904-01-01 UTC
          return d.getFullYear() >= 1980 && d <= new Date(Date.now() + 864e5) ? d : null;
        }
        if (s < 8) break;
        p += s;
      }
      return null;
    }
    off += size;
  }
  return null;
}

async function captureDate(file, kind) {
  try {
    const d = kind === 'image' ? await exifDate(file) : await movieDate(file);
    if (d) return d;
  } catch (e) { console.warn('date parse failed', e); }
  return file.lastModified ? new Date(file.lastModified) : new Date();
}

function uniquePath(date, name) {
  const stamp = `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
  let clean = name.normalize('NFKD').replace(/[^\w.-]+/g, '_').replace(/^[_.]+|_+$/g, '') || 'file';
  const ext = extOf(clean);
  const base = ext ? clean.slice(0, -(ext.length + 1)) : clean;
  const dir = `${MEDIA_DIR}/${date.getFullYear()}/${pad(date.getMonth() + 1)}`;
  let p = `${dir}/${stamp}_${base}${ext ? '.' + ext : ''}`;
  for (let i = 1; S.reserved.has(p); i++) p = `${dir}/${stamp}_${base}-${i}${ext ? '.' + ext : ''}`;
  S.reserved.add(p);
  return p;
}

// ---------------------------------------------------------------- encoding helpers
async function gitBlobSha(buf) {
  const header = new TextEncoder().encode(`blob ${buf.byteLength}\0`);
  const all = new Uint8Array(header.length + buf.byteLength);
  all.set(header);
  all.set(new Uint8Array(buf), header.length);
  const h = new Uint8Array(await crypto.subtle.digest('SHA-1', all));
  return [...h].map(b => b.toString(16).padStart(2, '0')).join('');
}
function toBase64(blob) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(',')[1] || '');
    r.onerror = () => reject(r.error || new Error('Could not read file'));
    r.readAsDataURL(blob);
  });
}

// ---------------------------------------------------------------- thumbnails
function loadImageEl(file) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => resolve({ el: img, w: img.naturalWidth, h: img.naturalHeight, done: () => URL.revokeObjectURL(url) });
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('image decode')); };
    img.src = url;
  });
}
function loadVideoFrame(file) {
  return new Promise((resolve, reject) => {
    const v = document.createElement('video');
    const url = URL.createObjectURL(file);
    const done = () => { v.removeAttribute('src'); v.load(); URL.revokeObjectURL(url); };
    const timer = setTimeout(() => { done(); reject(new Error('video thumbnail timeout')); }, 12000);
    v.muted = true; v.playsInline = true; v.preload = 'auto';
    v.setAttribute('playsinline', ''); v.setAttribute('muted', '');
    v.onloadeddata = () => { v.currentTime = Math.min(1, (v.duration || 0) / 10); };
    v.onseeked = () => { clearTimeout(timer); resolve({ el: v, w: v.videoWidth, h: v.videoHeight, done }); };
    v.onerror = () => { clearTimeout(timer); done(); reject(new Error('video decode')); };
    v.src = url;
    v.load();
  });
}
async function makeThumb(file, kind) {
  const src = kind === 'image' ? await loadImageEl(file) : await loadVideoFrame(file);
  try {
    if (!src.w || !src.h) return null;
    const scale = Math.min(1, THUMB_PX / Math.min(src.w, src.h));
    const c = document.createElement('canvas');
    c.width = Math.max(1, Math.round(src.w * scale));
    c.height = Math.max(1, Math.round(src.h * scale));
    c.getContext('2d').drawImage(src.el, 0, 0, c.width, c.height);
    return await new Promise(r => c.toBlob(r, 'image/jpeg', 0.72));
  } finally {
    src.done();
  }
}

// ---------------------------------------------------------------- uploading
function uploadRow(file) {
  const li = document.createElement('li');
  li.innerHTML = '<div class="u-row"><span class="u-name"></span><span class="u-status">Waiting…</span></div><div class="u-bar"><i></i></div>';
  li.querySelector('.u-name').textContent = file.name;
  $('#upload-list').append(li);
  return {
    status(text, cls = '') { li.querySelector('.u-status').textContent = text; li.className = cls; },
    progress(p) { li.querySelector('.u-bar i').style.width = `${Math.round(Math.min(1, p) * 100)}%`; },
  };
}

async function prepare(job) {
  const { file, row, kind } = job;
  if (!kind) throw new Error('Not a photo or video');
  if (file.size > MAX_FILE) throw new Error(`Too large (${fmtSize(file.size)}); limit is ${fmtSize(MAX_FILE)}`);

  row.status('Checking…');
  const nParts = Math.max(1, Math.ceil(file.size / CHUNK));
  const firstBuf = await file.slice(0, Math.min(file.size, CHUNK)).arrayBuffer();
  const key = await gitBlobSha(firstBuf);
  if (S.shas.has(key) || S.pending.has(key)) {
    row.status('Already backed up', 'skip');
    return { job, skip: true };
  }
  S.pending.add(key);
  job.key = key;

  try {
    const date = await captureDate(file, kind);
    const path = uniquePath(date, file.name);
    job.path = path;
    const entries = [];
    const parts = [];
    row.status(nParts > 1 ? `Uploading 1/${nParts}…` : 'Uploading…');
    for (let i = 0; i < nParts; i++) {
      if (nParts > 1) row.status(`Uploading ${i + 1}/${nParts}…`);
      const slice = file.slice(i * CHUNK, Math.min(file.size, (i + 1) * CHUNK));
      const blob = await postBlob(await toBase64(slice), p => row.progress((i + p) / nParts * 0.95));
      const repoPath = nParts > 1 ? `${path}.parts/part-${String(i).padStart(3, '0')}` : path;
      entries.push({ path: repoPath, mode: '100644', type: 'blob', sha: blob.sha });
      parts.push({ sha: blob.sha, size: slice.size, path: repoPath });
    }

    let thumbSha = null;
    try {
      row.status('Making preview…');
      const t = await makeThumb(file, kind);
      if (t) {
        thumbSha = (await postBlob(await toBase64(t))).sha;
        entries.push({ path: thumbPath(path), mode: '100644', type: 'blob', sha: thumbSha });
      }
    } catch (e) { console.warn('No thumbnail for', file.name, e); }

    row.progress(1);
    return { job, entries, item: makeItem(path, parts), thumbSha };
  } catch (e) {
    S.pending.delete(key);
    if (job.path) S.reserved.delete(job.path);
    throw e;
  }
}

function deviceName() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return 'iPad';
  if (/Android/.test(ua)) return 'Android';
  if (/Macintosh/.test(ua)) return 'Mac';
  if (/Windows/.test(ua)) return 'Windows';
  return 'browser';
}

async function uploadFiles(fileList) {
  const files = [...fileList];
  if (!files.length) return;
  const panel = $('#uploads');
  if (!S.uploads) $('#upload-list').textContent = '';
  panel.hidden = false;
  panel.classList.remove('collapsed');
  $('#up-toggle').textContent = 'Hide';
  S.uploads++;
  updateUploadTitle();

  let wake = null;
  try { wake = await navigator.wakeLock?.request('screen'); } catch {}

  const jobs = files.map(f => ({ file: f, row: uploadRow(f), kind: kindOfFile(f) }));
  // Group into commits: a few files / ~150 MB per commit.
  const groups = [];
  let cur = [], bytes = 0;
  for (const j of jobs) {
    if (cur.length && (cur.length >= BATCH_FILES || bytes + j.file.size > BATCH_BYTES)) { groups.push(cur); cur = []; bytes = 0; }
    cur.push(j); bytes += j.file.size;
  }
  if (cur.length) groups.push(cur);

  const prepLimit = limiter(2);
  let saved = 0, skipped = 0, failed = 0;
  for (const group of groups) {
    const prepared = (await Promise.all(group.map(j => prepLimit(() => prepare(j)).catch(err => {
      j.row.status(err.message, 'err');
      failed++;
      return null;
    })))).filter(Boolean);
    const ready = prepared.filter(p => !p.skip);
    skipped += prepared.length - ready.length;
    if (!ready.length) continue;
    ready.forEach(p => p.job.row.status('Saving…'));
    try {
      await commitEntries(ready.flatMap(p => p.entries), `Add ${ready.length} file${ready.length > 1 ? 's' : ''} from ${deviceName()}`);
      for (const p of ready) {
        S.items.push(p.item);
        if (p.thumbSha) S.thumbs.set(p.item.path, p.thumbSha);
        p.job.row.status('Backed up', 'ok');
        saved++;
      }
      sortItems();
      renderGallery();
    } catch (err) {
      for (const p of ready) { p.job.row.status(`Not saved: ${err.message}`, 'err'); S.reserved.delete(p.item.path); }
      failed += ready.length;
    } finally {
      ready.forEach(p => S.pending.delete(p.job.key));
    }
  }

  try { await wake?.release(); } catch {}
  S.uploads--;
  updateUploadTitle(true);
  const bits = [];
  if (saved) bits.push(`${saved} backed up`);
  if (skipped) bits.push(`${skipped} already there`);
  if (failed) bits.push(`${failed} failed`);
  toast(bits.join(' · ') || 'Nothing to upload');
  if (!failed && !S.uploads) setTimeout(() => { if (!S.uploads) panel.hidden = true; }, 4000);
}

function updateUploadTitle(finished = false) {
  $('#up-title').textContent = S.uploads ? 'Uploading…' : (finished ? 'Upload finished' : 'Uploads');
  $('#up-note').hidden = !S.uploads;
}

// ---------------------------------------------------------------- deleting
async function deleteItems(items) {
  if (!items.length) return false;
  const what = items.length === 1 ? `"${items[0].displayName}"` : `${items.length} items`;
  if (!confirm(`Delete ${what} from your GitHub backup?\n\nThis cannot be undone from the app.`)) return false;
  const entries = [];
  for (const it of items) {
    for (const p of it.parts) entries.push({ path: p.path, mode: '100644', type: 'blob', sha: null });
    if (S.thumbs.has(it.path)) entries.push({ path: thumbPath(it.path), mode: '100644', type: 'blob', sha: null });
  }
  try {
    await commitEntries(entries, `Delete ${items.length} file${items.length > 1 ? 's' : ''}`);
  } catch (e) {
    toast(`Delete failed: ${e.message}`);
    return false;
  }
  const gone = new Set(items.map(i => i.path));
  S.items = S.items.filter(i => !gone.has(i.path));
  gone.forEach(p => { S.thumbs.delete(p); S.reserved.delete(p); S.selected.delete(p); });
  sortItems();
  renderGallery();
  toast(`Deleted ${what}`);
  return true;
}

// ---------------------------------------------------------------- saving to device
async function saveFiles(files) {
  const touch = matchMedia('(hover: none)').matches;
  if (touch && navigator.canShare?.({ files })) {
    try { await navigator.share({ files }); return; }
    catch (e) {
      if (e.name === 'AbortError') return;
      // NotAllowedError (user activation expired) → offer a button so the share has a fresh tap
      if (e.name === 'NotAllowedError') {
        toast(`${files.length} file${files.length > 1 ? 's' : ''} ready`, { label: 'Save', fn: () => saveFiles(files) }, 15000);
        return;
      }
    }
  }
  for (const f of files) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(f);
    a.download = f.name;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 60000);
    if (files.length > 1) await sleep(400);
  }
}
async function itemFile(item) {
  const { blob } = await fullMedia(item);
  return new File([blob], item.displayName, { type: item.mime, lastModified: +item.date });
}

// ---------------------------------------------------------------- formatting
function fmtSize(b) {
  if (b < 1024) return `${b} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
  return `${b.toFixed(b < 10 ? 1 : 0)} ${u[i]}`;
}
const monthFmt = new Intl.DateTimeFormat(undefined, { month: 'long', year: 'numeric' });
const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

let toastTimer;
function toast(msg, action, ms = 3500) {
  const t = $('#toast');
  t.textContent = msg;
  if (action) {
    const b = document.createElement('button');
    b.className = 'btn small primary';
    b.style.marginLeft = '10px';
    b.textContent = action.label;
    b.onclick = () => { t.hidden = true; action.fn(); };
    t.append(b);
  }
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, ms);
}

// ---------------------------------------------------------------- gallery rendering
const PLAY_ICON = '<svg viewBox="0 0 24 24"><path d="M7 4v16l13-8z"/></svg>';
const PREVIEWABLE = /^image\/(jpeg|png|gif|webp|avif|bmp)$/;
const io = new IntersectionObserver(entries => {
  for (const en of entries) {
    if (!en.isIntersecting) continue;
    io.unobserve(en.target);
    loadTile(en.target);
  }
}, { rootMargin: '600px 0px' });

async function loadTile(tile) {
  const item = S.byPath.get(tile.dataset.path);
  if (!item) return;
  let sha = S.thumbs.get(item.path), mime = 'image/jpeg';
  if (!sha && item.kind === 'image' && item.parts.length === 1 && item.size < 6e6 && PREVIEWABLE.test(item.mime)) {
    sha = item.parts[0].sha; mime = item.mime;
  }
  if (!sha) return placeholder(tile, item);
  try {
    const url = await thumbURL(sha, mime);
    const img = document.createElement('img');
    img.alt = '';
    img.decoding = 'async';
    img.onload = () => img.classList.add('on');
    img.onerror = () => { img.remove(); placeholder(tile, item); };
    img.src = url;
    tile.prepend(img);
  } catch {
    placeholder(tile, item);
  }
}
function placeholder(tile, item) {
  if (tile.querySelector('.ph')) return;
  const d = document.createElement('div');
  d.className = 'ph';
  d.textContent = extOf(item.name).toUpperCase();
  tile.prepend(d);
}

function renderGallery() {
  S.view = S.items.filter(i => S.filter === 'all' || i.kind === S.filter);
  const g = $('#gallery');
  io.disconnect();
  g.textContent = '';
  const frag = document.createDocumentFragment();
  let month = null, grid = null;
  S.view.forEach((it, idx) => {
    const mk = `${it.date.getFullYear()}-${it.date.getMonth()}`;
    if (mk !== month) {
      month = mk;
      const h = document.createElement('h2');
      h.className = 'month';
      h.innerHTML = '<span></span>';
      h.firstChild.textContent = it.date.getTime() ? monthFmt.format(it.date) : 'Unknown date';
      grid = document.createElement('div');
      grid.className = 'grid';
      frag.append(h, grid);
    }
    const t = document.createElement('button');
    t.className = 'tile' + (S.selected.has(it.path) ? ' sel' : '');
    t.dataset.idx = idx;
    t.dataset.path = it.path;
    t.setAttribute('aria-label', it.displayName);
    t.innerHTML = (it.kind === 'video' ? `<span class="badge">${PLAY_ICON}</span>` : '') + '<span class="chk"></span>';
    grid.append(t);
    io.observe(t);
  });
  g.append(frag);

  $('#empty').hidden = S.items.length > 0;
  const photos = S.items.filter(i => i.kind === 'image').length;
  const total = S.items.reduce((s, i) => s + i.size, 0);
  $('#stats').textContent = S.items.length
    ? `${photos.toLocaleString()} photos · ${(S.items.length - photos).toLocaleString()} videos · ${fmtSize(total)}`
    : '';
  updateBanner();
  updateSelbar();
}

// ---------------------------------------------------------------- selection
function setSelecting(on) {
  S.selecting = on;
  if (!on) S.selected.clear();
  document.body.classList.toggle('selecting', on);
  document.querySelectorAll('.tile.sel').forEach(t => t.classList.toggle('sel', S.selected.has(t.dataset.path)));
  $('#btn-select').textContent = on ? 'Cancel' : 'Select';
  updateSelbar();
}
function updateSelbar() {
  $('#selbar').hidden = !S.selecting;
  const n = S.selected.size;
  $('#sel-count').textContent = `${n} selected`;
  $('#sel-download').disabled = $('#sel-delete').disabled = !n;
}

// ---------------------------------------------------------------- viewer
let viewerToken = 0;
async function openViewer(idx) {
  if (idx < 0 || idx >= S.view.length) return;
  S.viewIndex = idx;
  const it = S.view[idx];
  const token = ++viewerToken;
  $('#viewer').hidden = false;
  document.body.classList.add('noscroll');
  $('#v-title').textContent = it.displayName;
  $('#v-meta').textContent = `${it.date.getTime() ? dateFmt.format(it.date) : 'Unknown date'} · ${fmtSize(it.size)}`;
  $('#v-prev').disabled = idx === 0;
  $('#v-next').disabled = idx === S.view.length - 1;
  const stage = $('#v-stage');
  stage.innerHTML = '<div class="msg"><div class="spinner"></div><span>Loading…</span></div>';
  try {
    const { url } = await fullMedia(it, (i, n) => {
      if (token === viewerToken && n > 1) stage.querySelector('.msg span').textContent = `Loading ${Math.round(i / n * 100)}%…`;
    });
    if (token !== viewerToken) return;
    let el;
    if (it.kind === 'video') {
      el = document.createElement('video');
      el.controls = true; el.playsInline = true; el.autoplay = true;
      el.setAttribute('playsinline', '');
    } else {
      el = document.createElement('img');
      el.alt = it.displayName;
    }
    el.onerror = () => {
      if (token !== viewerToken) return;
      stage.innerHTML = `<div class="msg">This browser can't display ${extOf(it.name).toUpperCase()} files.<br>Use the download button to open it on your device.</div>`;
    };
    el.src = url;
    stage.replaceChildren(el);
    // warm the next item if it's a photo
    const nxt = S.view[idx + 1];
    if (nxt && nxt.kind === 'image' && nxt.size < 15e6) fullMedia(nxt).catch(() => {});
  } catch (e) {
    if (token === viewerToken) stage.innerHTML = '<div class="msg"></div>', stage.firstChild.textContent = `Couldn't load: ${e.message}`;
  }
}
function closeViewer() {
  viewerToken++;
  $('#viewer').hidden = true;
  $('#v-stage').textContent = '';
  document.body.classList.remove('noscroll');
}

// ---------------------------------------------------------------- settings
function openSettings() {
  const info = $('#settings-info');
  const total = S.items.reduce((s, i) => s + i.size, 0);
  const rows = [
    ['Signed in as', S.user?.login || '—'],
    ['Repository', `${S.cfg.owner}/${S.cfg.repo}${S.repoInfo?.private === false ? ' (PUBLIC!)' : ' (private)'}`],
    ['Branch', S.branch],
    ['Items', S.items.length.toLocaleString()],
    ['Media size', fmtSize(total)],
    ['Repository size', fmtSize((S.repoInfo?.size || 0) * 1024) + ' (includes history)'],
  ];
  info.textContent = '';
  for (const [k, v] of rows) {
    const dt = document.createElement('dt'); dt.textContent = k;
    const dd = document.createElement('dd'); dd.textContent = v;
    info.append(dt, dd);
  }
  $('#s-open').href = S.repoInfo?.html_url || `https://github.com/${S.cfg.owner}/${S.cfg.repo}`;
  $('#settings').showModal();
}

// ---------------------------------------------------------------- screens
function showSetup(error, cfg) {
  $('#app').hidden = true;
  $('#setup').hidden = false;
  $('#lock').hidden = true;
  if (cfg?.owner) $('#f-repo').value = `${cfg.owner}/${cfg.repo}`;
  const err = $('#setup-error');
  err.hidden = !error;
  err.textContent = error || '';
}
function showApp() {
  $('#setup').hidden = true;
  $('#lock').hidden = true;
  $('#app').hidden = false;
  updateBanner();
}
function updateBanner() {
  const repoBytes = (S.repoInfo?.size || 0) * 1024;
  let msg = '';
  if (S.repoInfo?.private === false) msg = '⚠ This repository is PUBLIC — anyone can see your photos. Make it private in the repository settings on GitHub.';
  else if (S.truncated) msg = 'Your library is very large and GitHub returned only part of it. Consider a second repository.';
  else if (repoBytes > 4e9) msg = `This repository is about ${fmtSize(repoBytes)}. GitHub recommends keeping repositories under 5 GB; consider starting a second repository (e.g. one per year).`;
  $('#banner').textContent = msg;
  $('#banner').hidden = !msg;
}

// ---------------------------------------------------------------- events
function bind() {
  $('#setup-form').addEventListener('submit', async e => {
    e.preventDefault();
    const btn = $('#f-submit');
    const raw = $('#f-repo').value.trim().replace(/^https?:\/\/github\.com\//i, '').replace(/\.git$/, '').replace(/\/+$/, '');
    const [owner, repo, extra] = raw.split('/');
    if (!owner || !repo || extra) return showSetup('Enter the repository as owner/name, e.g. jane/my-photos.');
    const pw = $('#f-pass').value, pw2 = $('#f-pass2').value;
    if (pw.length < 6) return showSetup('Choose an app password of at least 6 characters.');
    if (pw !== pw2) return showSetup('The two passwords don\'t match.');
    const cfg = { token: $('#f-token').value.trim(), owner, repo };
    btn.disabled = true;
    btn.textContent = 'Connecting…';
    try {
      await connect(cfg, { create: $('#f-create').checked });
      await saveConfig(cfg, pw);
      $('#f-token').value = $('#f-pass').value = $('#f-pass2').value = '';
      showApp();
      await loadLibrary().catch(e => { throw new Error(`While reading your library: ${e.message}`); });
    } catch (err) {
      showSetup(err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Connect';
    }
  });

  $('#file-input').addEventListener('change', e => {
    const files = [...e.target.files];
    e.target.value = '';
    uploadFiles(files);
  });

  $('#filters').addEventListener('click', e => {
    const b = e.target.closest('button[data-filter]');
    if (!b) return;
    S.filter = b.dataset.filter;
    document.querySelectorAll('#filters button').forEach(x => x.classList.toggle('active', x === b));
    renderGallery();
  });

  $('#gallery').addEventListener('click', e => {
    const t = e.target.closest('.tile');
    if (!t) return;
    if (S.selecting) {
      const p = t.dataset.path;
      S.selected.has(p) ? S.selected.delete(p) : S.selected.add(p);
      t.classList.toggle('sel', S.selected.has(p));
      updateSelbar();
    } else {
      openViewer(+t.dataset.idx);
    }
  });

  $('#btn-refresh').addEventListener('click', () => loadLibrary().catch(err => toast(err.message)));
  $('#btn-select').addEventListener('click', () => setSelecting(!S.selecting));
  $('#sel-cancel').addEventListener('click', () => setSelecting(false));
  $('#sel-delete').addEventListener('click', async () => {
    const items = [...S.selected].map(p => S.byPath.get(p)).filter(Boolean);
    if (await deleteItems(items)) setSelecting(false);
  });
  $('#sel-download').addEventListener('click', async () => {
    const items = [...S.selected].map(p => S.byPath.get(p)).filter(Boolean);
    const btn = $('#sel-download');
    btn.disabled = true;
    btn.textContent = 'Preparing…';
    try {
      const files = [];
      for (const it of items) files.push(await itemFile(it));
      await saveFiles(files);
    } catch (e) {
      toast(`Download failed: ${e.message}`);
    } finally {
      btn.textContent = 'Download';
      updateSelbar();
    }
  });

  $('#up-toggle').addEventListener('click', () => {
    const p = $('#uploads');
    if (!S.uploads) { p.hidden = true; return; }
    p.classList.toggle('collapsed');
    $('#up-toggle').textContent = p.classList.contains('collapsed') ? 'Show' : 'Hide';
  });

  // viewer
  $('#v-close').addEventListener('click', closeViewer);
  $('#v-prev').addEventListener('click', () => openViewer(S.viewIndex - 1));
  $('#v-next').addEventListener('click', () => openViewer(S.viewIndex + 1));
  $('#v-download').addEventListener('click', async () => {
    const it = S.view[S.viewIndex];
    try { await saveFiles([await itemFile(it)]); } catch (e) { toast(`Download failed: ${e.message}`); }
  });
  $('#v-delete').addEventListener('click', async () => {
    const idx = S.viewIndex;
    if (!(await deleteItems([S.view[idx]]))) return;
    if (!S.view.length) return closeViewer();
    openViewer(Math.min(idx, S.view.length - 1));
  });
  document.addEventListener('keydown', e => {
    if ($('#viewer').hidden) return;
    if (e.key === 'Escape') closeViewer();
    else if (e.key === 'ArrowLeft') openViewer(S.viewIndex - 1);
    else if (e.key === 'ArrowRight') openViewer(S.viewIndex + 1);
  });
  let touchX = null, touchY = null;
  $('#v-stage').addEventListener('touchstart', e => { touchX = e.touches[0].clientX; touchY = e.touches[0].clientY; }, { passive: true });
  $('#v-stage').addEventListener('touchend', e => {
    if (touchX === null) return;
    const dx = e.changedTouches[0].clientX - touchX, dy = e.changedTouches[0].clientY - touchY;
    touchX = null;
    if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy) * 1.5) openViewer(S.viewIndex + (dx < 0 ? 1 : -1));
    else if (dy > 120 && Math.abs(dy) > Math.abs(dx) * 1.5) closeViewer();
  });

  // settings
  $('#btn-settings').addEventListener('click', openSettings);
  $('#s-close').addEventListener('click', () => $('#settings').close());
  $('#s-logout').addEventListener('click', async () => {
    if (!confirm('Disconnect this device? Your photos stay safe on GitHub.')) return;
    await forget();
  });
  $('#s-password').addEventListener('click', () => { $('#settings').close(); $('#pw-form').reset(); $('#pw-error').hidden = true; $('#pw-dialog').showModal(); });
  $('#pw-cancel').addEventListener('click', () => $('#pw-dialog').close());
  $('#pw-form').addEventListener('submit', async e => {
    e.preventDefault();
    const err = $('#pw-error');
    const fail = m => { err.textContent = m; err.hidden = false; };
    const [cur, n1, n2] = ['#pw-cur', '#pw-new', '#pw-new2'].map(id => $(id).value);
    if (n1.length < 6) return fail('The new password must be at least 6 characters.');
    if (n1 !== n2) return fail('The new passwords don\'t match.');
    try { await openToken(store.get().sealed, cur); } catch { return fail('Current password is wrong.'); }
    await saveConfig(S.cfg, n1);
    $('#pw-dialog').close();
    toast('Password changed');
  });

  // lock screen
  $('#btn-lock').addEventListener('click', lock);
  $('#lock-form').addEventListener('submit', async e => {
    e.preventDefault();
    await unlock($('#l-pass').value);
  });
  $('#l-forgot').addEventListener('click', async () => {
    if (!confirm('Reset this device?\n\nYour photos stay safe on GitHub. You will need to enter your GitHub token again and choose a new password.')) return;
    await forget();
  });

  // auto-lock after inactivity, or when the app was in the background for a while
  let lastActive = Date.now(), hiddenAt = 0;
  for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart']) window.addEventListener(ev, () => { lastActive = Date.now(); }, { passive: true });
  setInterval(() => { if (S.cfg && !S.uploads && Date.now() - lastActive > AUTO_LOCK_MS) lock(); }, 20000);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) hiddenAt = Date.now();
    else if (S.cfg && !S.uploads && hiddenAt && Date.now() - hiddenAt > AUTO_LOCK_MS / 2) lock();
  });

  // drag & drop (desktop)
  let depth = 0;
  const hasFiles = e => [...(e.dataTransfer?.types || [])].includes('Files');
  window.addEventListener('dragenter', e => { if (hasFiles(e) && !$('#app').hidden) { depth++; $('#drop').hidden = false; } });
  window.addEventListener('dragleave', () => { if (--depth <= 0) { depth = 0; $('#drop').hidden = true; } });
  window.addEventListener('dragover', e => { if (hasFiles(e)) e.preventDefault(); });
  window.addEventListener('drop', e => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth = 0;
    $('#drop').hidden = true;
    if (!$('#app').hidden) uploadFiles(e.dataTransfer.files);
  });

  window.addEventListener('beforeunload', e => {
    if (S.uploads) { e.preventDefault(); e.returnValue = ''; }
  });
}

// ---------------------------------------------------------------- boot
async function boot() {
  bind();
  if ('serviceWorker' in navigator && location.protocol === 'https:') {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
  try { localStorage.removeItem('gitvault:v1'); sessionStorage.removeItem('gitvault:v1'); } catch {} // drop pre-password format
  const saved = store.get();
  if (!saved?.sealed) return showSetup();
  showLock();
}

function showLock(error) {
  $('#setup').hidden = true;
  $('#app').hidden = true;
  $('#lock').hidden = false;
  const saved = store.get();
  $('#lock-repo').textContent = saved ? `${saved.owner}/${saved.repo}` : '';
  const err = $('#lock-error');
  err.hidden = !error;
  err.textContent = error || '';
  $('#l-pass').value = '';
  setTimeout(() => $('#l-pass').focus(), 50);
}

let failedUnlocks = 0;
async function unlock(password) {
  const btn = $('#l-submit');
  const saved = store.get();
  if (!saved?.sealed) return showSetup();
  btn.disabled = true;
  btn.textContent = 'Unlocking…';
  try {
    let token;
    try {
      token = await openToken(saved.sealed, password);
    } catch (e) {
      failedUnlocks++;
      await sleep(Math.min(30000, 500 * 2 ** failedUnlocks)); // slow down guessing
      return showLock(failedUnlocks >= 3 ? `Wrong password (${failedUnlocks} attempts).` : 'Wrong password.');
    }
    failedUnlocks = 0;
    const cfg = { token, owner: saved.owner, repo: saved.repo };
    $('#lock').hidden = true;
    $('#app').hidden = false;
    $('#loading').hidden = false;
    try {
      await connect(cfg);
      showApp();
      await loadLibrary();
    } catch (e) {
      $('#loading').hidden = true;
      if (e.status === 401 || e.status === 403 || e.status === 404) {
        showSetup(`${e.message} Enter a new token to reconnect.`, cfg);
      } else {
        S.cfg = null;
        showLock(e.message);
      }
    }
  } finally {
    btn.disabled = false;
    btn.textContent = 'Unlock';
  }
}

/** Lock: reload the page so the token, images and URLs are wiped from memory. */
function lock() {
  if (S.uploads) return toast('Can\'t lock while an upload is running.');
  S.cfg = null;
  location.reload();
}

async function forget() {
  store.clear();
  try { await caches.delete('gitvault-thumbs-v1'); } catch {}
  S.cfg = null;
  location.reload();
}

boot();
