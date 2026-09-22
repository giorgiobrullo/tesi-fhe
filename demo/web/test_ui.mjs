import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const appSource = readFileSync(new URL('static/app.js', import.meta.url), 'utf8');
const htmlSource = readFileSync(new URL('static/index.html', import.meta.url), 'utf8');
const sharedSource = readFileSync(new URL('../dual_view/static/shared.js', import.meta.url), 'utf8');
const settle = function () { return new Promise(function (resolve) { setImmediate(resolve); }); };

function deferred() {
  let resolve;
  const promise = new Promise(function (done) { resolve = done; });
  return { promise, resolve };
}

// Minimal DOM for state and event tests. Visual verification uses the real local page.
function page(api, { start = false, media, fetch: fetchPhoto, readPhotos } = {}) {
  const elements = new Map();
  const windowListeners = {};
  const timers = new Map();
  const streams = [];
  let timerId = 0;
  let document;
  class FakeEventSource {
    constructor(url) {
      this.url = url;
      this.listeners = {};
      this.closed = false;
      streams.push(this);
    }
    addEventListener(name, listener) { (this.listeners[name] ||= []).push(listener); }
    close() { this.closed = true; }
    // Permit queued events after close so stale-connection guards are exercised.
    emit(name, data) {
      const event = { data: JSON.stringify(data) };
      for (const listener of this.listeners[name] || []) listener(event);
    }
  }
  class Element {
    constructor(tag = 'div') {
      this.tagName = tag.toUpperCase();
      this.dataset = {};
      this.attributes = {};
      this.style = {};
      this.listeners = {};
      this.children = [];
      this.textContent = '';
      this.value = '';
      this.hidden = false;
      this.disabled = false;
      this.open = false;
      this.files = [];
    }
    append(...children) { for (const child of children) { child.parent = this; this.children.push(child); } }
    replaceChildren(...children) { this.children = []; this.append(...children); }
    addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); }
    async emit(name, event = {}) { for (const listener of this.listeners[name] || []) await listener(event); }
    setAttribute(name, value) { this.attributes[name] = String(value); if (name === 'class') this.className = String(value); }
    getAttribute(name) { return this.attributes[name] ?? null; }
    focus() { document.activeElement = this; }
    scrollIntoView() {}
    showModal() { this.open = true; }
    close() { if (this.open) { this.open = false; this.emit('close'); } }
    reset() {}
    reportValidity() { return true; }
    play() { return Promise.resolve(); }
    matches(selector) {
      if (selector.startsWith('.')) return (this.className || '').split(/\s+/).includes(selector.slice(1));
      if (selector === '[data-person-id]') return this.dataset.personId !== undefined;
      if (selector === '[data-request-id]') return this.dataset.requestId !== undefined;
      if (selector === '[data-credit-id]') return this.dataset.creditId !== undefined;
      if (selector === 'details[open]') return this.tagName === 'DETAILS' && this.open;
      return this.tagName === selector.toUpperCase();
    }
    closest(selector) { return this.matches(selector) ? this : this.parent?.closest(selector); }
    querySelectorAll(selector) {
      return this.children.flatMap(function (child) {
        return [...(child.matches(selector) ? [child] : []), ...child.querySelectorAll(selector)];
      });
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  }
  function get(id) {
    if (!elements.has(id)) elements.set(id, new Element(id.endsWith('-dialog') ? 'dialog' : 'div'));
    return elements.get(id);
  }
  document = {
    activeElement: null,
    getElementById: get,
    createElement: function (tag) { return new Element(tag); },
    createElementNS: function (namespace, tag) { const element = new Element(tag); element.namespaceURI = namespace; return element; },
  };
  const context = vm.createContext({
    api, document, URL, EventSource: FakeEventSource,
    location: { origin: 'http://127.0.0.1:8010' },
    fetch: fetchPhoto || (async function () { throw new Error('Unexpected photo fetch'); }),
    FileReader: class {
      readAsDataURL(blob) {
        blob.arrayBuffer().then((bytes) => {
          this.result = `data:${blob.type};base64,${Buffer.from(bytes).toString('base64')}`;
          this.onload();
        }).catch(() => this.onerror());
      }
    },
    window: { addEventListener(name, callback) { windowListeners[name] = callback; } },
    navigator: { mediaDevices: { getUserMedia: media || (async function () { throw new Error('No camera'); }) } },
    mountIcons() {}, icon() { return new Element('svg'); },
    duration(value) { return `${value} ms`; },
    readPhotos: readPhotos || (async function () { return ['data:image/jpeg;base64,local']; }),
    renderPreviews: function (element, frames) { element.replaceChildren(...frames.map(function () { return new Element('img'); })); },
    setTimeout(fn, delay) { timers.set(++timerId, { fn, delay }); return timerId; },
    clearTimeout(id) { timers.delete(id); },
  });
  const cameraSource = sharedSource.slice(sharedSource.indexOf('export class Camera'), sharedSource.indexOf('export function renderPreviews')).replace('export class', 'class');
  vm.runInContext(cameraSource, context);
  vm.runInContext(sharedSource.slice(sharedSource.indexOf('export function galleryPhotoURL')).replace('export function', 'function'), context);
  let script = appSource.replace(/^import .*;\n/, '');
  if (!start) script = script.replace(/connectEvents\(\);\s*$/, '');
  vm.runInContext(script, context);
  return {
    run: function (code) { return vm.runInContext(code, context); }, get, windowListeners, timers, streams, document,
    async fireTimer(delay) {
      const found = Array.from(timers).find(function ([, timer]) { return timer.delay === delay; });
      assert.ok(found, `No timer scheduled for ${delay} ms`);
      timers.delete(found[0]);
      found[1].fn();
      await settle();
    },
  };
}

const readyStatus = { pronto: true, motori: [{ id: 'attuale', pronto: true }], sessione: { scadenza: '2026-09-20T22:00:00Z' } };
const empty = { iscritti: [], richieste: [], totale: 0 };
// Binary transport fixture: no image decoding or JPEG re-encoding belongs in this path.
const jpegBytes = Buffer.from([255, 216, 255, 224, 0, 16, 74, 70, 73, 70, 0, 1, 2, 0, 253, 254, 255, 217]);
const jpegBlob = new Blob([jpegBytes], { type: 'image/jpeg' });

function textOf(element) {
  return [element.textContent, ...element.children.map(textOf)].filter(Boolean).join(' ');
}

test('session bootstrap precedes one stream and snapshots never trigger REST polling', async function () {
  const status = deferred();
  const paths = [];
  const ui = page(function (path) {
    paths.push(path);
    return path === '/api/stato' ? status.promise : Promise.resolve(empty);
  }, { start: true });
  assert.deepEqual(paths, ['/api/stato']);
  assert.equal(ui.streams.length, 0);
  status.resolve(readyStatus);
  await settle();
  assert.deepEqual(paths, ['/api/stato']);
  assert.equal(ui.streams.length, 1);
  const stream = ui.streams[0];
  assert.equal(stream.url, '/api/eventi');
  stream.emit('stato', readyStatus);
  stream.emit('galleria', { iscritti: [{ id: 'ada', nome: 'Ada', soglia: 273 }] });
  stream.emit('richieste', { richieste: [], totale: 0 });
  for (let tick = 0; tick < 20; tick += 1) stream.emit('richieste', { richieste: [], totale: 0 });
  assert.equal(ui.run('state.people[0].id'), 'ada');
  assert.deepEqual(paths, ['/api/stato']);
  assert.equal(ui.timers.size, 0, 'a healthy stream has no polling or reconnect timer');
});

function initialEvents(stream, people = [{ id: 'ada', nome: 'Ada', soglia: 273 }]) {
  stream.emit('stato', readyStatus);
  stream.emit('galleria', { iscritti: people, totale: people.length });
  stream.emit('richieste', { richieste: [], totale: 0 });
}

test('pushed completion before the POST202 response is displayed without another read', async function () {
  const response = deferred();
  const calls = [];
  const ui = page(function (path) {
    calls.push(path);
    if (path === '/api/stato') return Promise.resolve(readyStatus);
    if (path === '/api/accesso') return response.promise;
    throw new Error(`Unexpected API ${path}`);
  }, { start: true });
  await settle();
  const stream = ui.streams[0];
  initialEvents(stream);
  ui.get('probe-files').files = [{ name: 'photo.jpg' }];
  await ui.get('probe-files').emit('change');
  const submitting = ui.run('submitProbe()');
  await settle();
  stream.emit('richieste', { richieste: [{ id: 'fast', stato: 'completata', motore: 'attuale',
    risultati: [{ motore: 'attuale', esito: 'aperto', selected_name: 'Ada' }] }], totale: 1 });
  assert.equal(ui.run('state.latestId'), null);
  assert.equal(ui.run('state.requests[0].stato'), 'completata');
  response.resolve({ richiesta_id: 'fast' });
  await submitting;
  assert.equal(ui.get('probe-result').hidden, false);
  assert.equal(ui.get('probe-progress').hidden, true);
  assert.equal(ui.get('probe-result').children[0].textContent, 'Accesso consentito · Ada');
  assert.deepEqual(calls, ['/api/stato', '/api/accesso']);
  assert.equal(ui.timers.size, 0);
});

test('push updates retain request expansion and use only server timeline ticks', async function () {
  const ui = page(async function () { return readyStatus; }, { start: true });
  await settle();
  const stream = ui.streams[0];
  initialEvents(stream);
  const request = { id: 'live', stato: 'elaborazione', motore: 'attuale', timeline: { elapsed_ms: 100, spans: [
    { id: 'job', parent_id: null, kind: 'job', start_ms: 0, end_ms: null },
    { id: 'attuale', parent_id: 'job', kind: 'engine', start_ms: 20, end_ms: null },
  ] } };
  stream.emit('richieste', { richieste: [request], totale: 1 });
  let details = ui.get('requests').querySelector('details');
  details.open = true;
  details.querySelector('summary').focus();
  assert.equal(details.querySelector('.timeline-engine').querySelector('rect').getAttribute('width'), '80');
  assert.equal(ui.timers.size, 0, 'the browser must not extrapolate progress with a local timer');
  request.timeline.elapsed_ms = 160;
  stream.emit('richieste', { richieste: [request], totale: 1 });
  details = ui.get('requests').querySelector('details');
  assert.equal(details.querySelector('.timeline-engine').querySelector('rect').getAttribute('width'), '140');
  assert.equal(details.open, true);
  assert.equal(ui.document.activeElement, details.querySelector('summary'));
});

test('REST reads started before newer push snapshots cannot roll the UI back', async function () {
  const oldGallery = deferred();
  const oldStatus = deferred();
  let statusCalls = 0;
  const ui = page(function (path) {
    if (path === '/api/galleria') return oldGallery.promise;
    if (path === '/api/stato') return ++statusCalls === 1 ? Promise.resolve(readyStatus) : oldStatus.promise;
    throw new Error(`Unexpected API ${path}`);
  }, { start: true });
  await settle();
  const stream = ui.streams[0];
  initialEvents(stream);
  const galleryRead = ui.run('loadGallery()');
  const statusRead = ui.run('loadStatus()');
  stream.emit('galleria', { iscritti: [{ id: 'new', nome: 'New', soglia: 250 }], totale: 1 });
  stream.emit('stato', readyStatus);
  oldGallery.resolve(empty);
  oldStatus.resolve({ pronto: false, motori: [], sessione: { scadenza: 'old-session' } });
  await Promise.all([galleryRead, statusRead]);
  assert.equal(ui.run('state.people[0].id'), 'new');
  assert.equal(ui.run('state.ready'), true);
  assert.equal(ui.run('state.sessionExpiry'), readyStatus.sessione.scadenza);
});

test('reconnect closes the old stream and backs off to a bounded delay until snapshots recover', async function () {
  let available = false;
  let calls = 0;
  const ui = page(async function (path) {
    assert.equal(path, '/api/stato');
    calls += 1;
    if (!available) throw new Error('Offline');
    return readyStatus;
  }, { start: true });
  await settle();
  for (const delay of [1000, 2000, 4000, 8000, 16000, 30000, 30000]) {
    assert.equal(ui.timers.size, 1);
    await ui.fireTimer(delay);
  }
  assert.equal(ui.streams.length, 0);
  assert.equal(calls, 8);
  available = true;
  await ui.fireTimer(30000);
  const stream = ui.streams[0];
  initialEvents(stream);
  assert.equal(ui.timers.size, 0);
  stream.emit('error');
  assert.equal(stream.closed, true);
  assert.equal(ui.run('state.connected'), false);
  stream.emit('error');
  assert.equal(ui.timers.size, 1, 'queued errors from a closed stream cannot add reconnects');
  await ui.fireTimer(1000);
  assert.equal(ui.streams.length, 2);
  initialEvents(ui.streams[1], [{ id: 'fresh', nome: 'Fresh', soglia: 273 }]);
  stream.emit('galleria', { iscritti: [], totale: 0 });
  assert.equal(ui.run('state.people[0].id'), 'fresh');
  assert.equal(ui.timers.size, 0);
});

test('session expiry clears photos immediately and ignores former stream and POST responses after renewal', async function () {
  const posted = deferred();
  const renewed = { ...readyStatus, sessione: { scadenza: '2026-09-20T23:00:00Z' } };
  let statusCalls = 0;
  const ui = page(function (path) {
    if (path === '/api/stato') return Promise.resolve(++statusCalls === 1 ? readyStatus : renewed);
    if (path === '/api/accesso') return posted.promise;
    throw new Error(`Unexpected API ${path}`);
  }, { start: true });
  await settle();
  const old = ui.streams[0];
  initialEvents(old);
  ui.get('probe-files').files = [{ name: 'photo.jpg' }];
  await ui.get('probe-files').emit('change');
  const submitting = ui.run('submitProbe()');
  await settle();
  old.emit('scaduta', { errore: 'Sessione scaduta. Ricarica la pagina.' });
  assert.equal(old.closed, true);
  assert.equal(ui.run('probeSource.hasInput'), false);
  assert.equal(ui.run('state.people.length'), 0);
  assert.equal(ui.run('state.requests.length'), 0);
  assert.equal(ui.run('state.submitting'), false);
  await ui.fireTimer(1000);
  const fresh = ui.streams[1];
  fresh.emit('stato', renewed);
  fresh.emit('galleria', { iscritti: [{ id: 'fresh', nome: 'Fresh', soglia: 273 }] });
  fresh.emit('richieste', { richieste: [], totale: 0 });
  old.emit('stato', readyStatus);
  old.emit('galleria', { iscritti: [{ id: 'old', nome: 'Old', soglia: 273 }] });
  old.emit('richieste', { richieste: [{ id: 'old', stato: 'completata' }] });
  posted.resolve({ richiesta_id: 'old' });
  await submitting;
  assert.equal(ui.run('state.sessionExpiry'), renewed.sessione.scadenza);
  assert.equal(ui.run('state.people[0].id'), 'fresh');
  assert.equal(ui.run('state.requests.length'), 0);
  assert.equal(ui.run('state.latestId'), null);
  assert.equal(ui.get('probe-result').hidden, true);
});

test('pagehide releases the stream and reconnect timer; BFCache recovery opens exactly one new stream', async function () {
  let calls = 0;
  const ui = page(async function () { calls += 1; return readyStatus; }, { start: true });
  await settle();
  const old = ui.streams[0];
  initialEvents(old);
  ui.windowListeners.pagehide();
  assert.equal(old.closed, true);
  old.emit('error');
  old.emit('galleria', { iscritti: [] });
  assert.equal(ui.timers.size, 0);
  ui.windowListeners.pageshow({ persisted: true });
  await settle();
  assert.equal(calls, 2);
  assert.equal(ui.streams.length, 2);
  const current = ui.streams[1];
  initialEvents(current);
  current.emit('error');
  assert.equal(ui.timers.size, 1);
  ui.windowListeners.pagehide();
  assert.equal(ui.timers.size, 0);
  ui.windowListeners.pageshow({ persisted: true });
  await settle();
  assert.equal(calls, 3);
  assert.equal(ui.streams.length, 3);
  assert.equal(ui.timers.size, 0);
});

test('missing embedding preparation blocks new work even with the current engine ready', async function () {
  const ui = page(async function () { return { ...readyStatus, pronto: false, errore: 'Modelli locali mancanti.' }; });
  await ui.run('loadStatus()');
  assert.equal(ui.run('state.connected'), true);
  assert.equal(ui.run('state.ready'), false);
  assert.equal(ui.get('add-person').disabled, true);
  assert.equal(ui.get('submit-probe').disabled, true);
  assert.equal(ui.get('engine-readiness').textContent, 'Modelli locali mancanti.');
});

test('the page offers only Verifica accesso without an engine or comparison selector', function () {
  assert.doesNotMatch(htmlSource, /engine-choice|engine-options|name=["']motore["']|Confronta entrambe|\bA28\b/);
  const submit = htmlSource.match(/<button\b[^>]*id=["']submit-probe["'][^>]*>([\s\S]*?)<\/button>/)?.[1];
  assert.ok(submit);
  assert.match(submit, /Verifica accesso/);
});

test('only current readiness enables work and every new access request uses the current engine', async function () {
  let status = { pronto: true, motori: [{ id: 'a28', pronto: true }] };
  const submitted = [];
  const ui = page(async function (path, options) {
    if (path === '/api/stato') return status;
    if (path === '/api/accesso') { submitted.push(options.body); return { richiesta_id: 'current-only' }; }
    if (path === '/api/richieste') return { richieste: [{ id: 'current-only', stato: 'completata', motore: 'attuale', risultati: [{ motore: 'attuale', esito: 'aperto', selected_name: 'Ada' }] }] };
    throw new Error(`Unexpected API ${path}`);
  });
  ui.run("state.people = [{id:'ada',nome:'Ada'}]");
  ui.get('probe-files').files = [{ name: 'photo.jpg' }];
  await ui.get('probe-files').emit('change');
  await ui.run('loadStatus()');
  assert.equal(ui.get('submit-probe').disabled, true, 'an available historical engine cannot enable a new query');
  assert.equal(ui.get('add-person').disabled, true);
  await ui.run('submitProbe()');
  assert.equal(submitted.length, 0);
  status = { pronto: true, motori: [{ id: 'attuale', pronto: false, errore: 'Verifica non disponibile.' }, { id: 'a28', pronto: true }] };
  await ui.run('loadStatus()');
  assert.equal(ui.get('submit-probe').disabled, true);
  assert.equal(ui.get('engine-readiness').textContent, 'Verifica non disponibile.');
  status = { pronto: false, motori: [{ id: 'attuale', pronto: true }] };
  await ui.run('loadStatus()');
  assert.equal(ui.get('submit-probe').disabled, true, 'the preparation readiness gate still applies');
  status = { pronto: true, motori: [{ id: 'attuale', pronto: true }, { id: 'a28', pronto: false, errore: 'Old engine unavailable.' }] };
  await ui.run('loadStatus()');
  assert.equal(ui.get('submit-probe').disabled, false);
  assert.equal(ui.get('add-person').disabled, false);
  assert.equal(ui.get('engine-readiness').textContent, 'Pronto per la verifica.');
  await ui.run('submitProbe()');
  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].motore, 'attuale');
  assert.deepEqual(Object.keys(submitted[0]).sort(), ['frames', 'motore']);
  ui.run("applyRequests({richieste:[{id:'current-only',stato:'completata',motore:'attuale',risultati:[{motore:'attuale',esito:'aperto',selected_name:'Ada'}]}]})");
  assert.equal(ui.get('probe-result').children[0].textContent, 'Accesso consentito · Ada');
});

test('gallery ignores an older response that arrives after the latest read', async function () {
  const old = deferred();
  const fresh = deferred();
  let calls = 0;
  const ui = page(function () { return ++calls === 1 ? old.promise : fresh.promise; });
  const first = ui.run('loadGallery()');
  const second = ui.run('loadGallery()');
  fresh.resolve({ iscritti: [{ id: 'new', nome: 'New', soglia: 273 }] });
  await second;
  old.resolve(empty);
  await first;
  assert.equal(ui.run('state.people[0].id'), 'new');
});

test('request details stay expanded and retain keyboard focus across state updates', function () {
  const ui = page(async function () { return empty; });
  ui.run("renderRequests([{id:'one', stato:'elaborazione', motore:'attuale'}])");
  const old = ui.get('requests').querySelector('details');
  old.open = true;
  old.querySelector('summary').focus();
  ui.run("renderRequests([{id:'one', stato:'completata', motore:'attuale', risultati:[{motore:'attuale',esito:'negato'}]}])");
  const current = ui.get('requests').querySelector('details');
  assert.equal(current.open, true);
  assert.equal(ui.document.activeElement, current.querySelector('summary'));
});

test('comparison preserves both results and never turns an error into denied access', function () {
  const ui = page(async function () { return empty; });
  const details = ui.run("requestDetails({stato:'completata',motore:'confronto',risultati:[{motore:'attuale',esito:'aperto',selected_name:'Ada'},{motore:'a28',esito:'negato'}]})");
  const groups = details.querySelectorAll('.waterfall-group');
  assert.equal(groups.length, 2);
  assert.match(textOf(groups[0]), /Attuale/);
  assert.equal(groups[0].querySelector('.waterfall-result').textContent, 'Accesso consentito · Ada');
  assert.match(textOf(groups[1]), /A28/);
  assert.equal(groups[1].querySelector('.waterfall-result').textContent, 'Accesso negato');
  ui.run("renderRequests([{id:'failed',stato:'errore',motore:'attuale',errore:'Timeout'}])");
  const failed = ui.get('requests').querySelector('article');
  assert.equal(failed.querySelector('.request-state').textContent, 'Errore nella verifica');
  assert.equal(failed.querySelector('.request-error').textContent, 'Timeout');
  assert.doesNotMatch(textOf(failed), /Accesso negato/);
  const unknown = ui.run("requestDetails({stato:'completata',motore:'attuale',risultati:[{motore:'attuale',esito:'sconosciuto'}]})");
  assert.equal(unknown.querySelector('.waterfall-result').textContent, 'Esito non disponibile');
});

test('total motor time cannot masquerade as queue-inclusive request time', function () {
  const ui = page(async function () { return empty; });
  const timings = ui.run("requestTimes({attesa_ms:20,risultati:[{motore:'attuale',tempi_ms:{server:5,totale:9}}]})");
  assert.equal(timings, 'Attesa 20 ms · Servizio FHE 5 ms');
  assert.doesNotMatch(timings, /Complessivo/);
});

test('the HTML header has no connection-status element', function () {
  const header = htmlSource.match(/<header\b[^>]*>([\s\S]*?)<\/header>/i)?.[1];
  assert.ok(header);
  assert.doesNotMatch(header, /(?:\bconnection\b|role=["']status["']|data-state=)/i);
  assert.doesNotMatch(htmlSource, /id=["']connection["']/i);
});

test('each request is a single expandable HTTP row with measured server elapsed time', function () {
  const ui = page(async function () { return empty; });
  ui.run("renderRequests([{id:'http-one',ora:'2026-09-21T10:00:00Z',stato:'completata',motore:'confronto',iscritti:120,tempo_complessivo_ms:950,risultati:[{motore:'attuale',esito:'aperto',selected_name:'Ada'},{motore:'a28',esito:'negato'}]}])");
  const articles = ui.get('requests').querySelectorAll('article');
  assert.equal(articles.length, 1);
  const article = articles[0];
  assert.equal(article.children.length, 1);
  const details = article.children[0];
  assert.equal(details.tagName, 'DETAILS');
  assert.equal(details.children[0].tagName, 'SUMMARY');
  assert.equal(details.open, false);
  assert.equal(article.querySelectorAll('summary').length, 1);
  const summary = details.children[0];
  assert.equal(summary.querySelector('.request-method').textContent, 'POST');
  assert.equal(summary.querySelector('code').textContent, '/api/accesso');
  assert.equal(summary.querySelector('.request-engine').textContent, 'Confronto');
  assert.equal(summary.querySelector('.request-state').textContent, 'Completata');
  assert.equal(summary.querySelector('time').dateTime, '2026-09-21T10:00:00.000Z');
  assert.equal(textOf(summary.querySelector('.request-duration')), '950 ms sul server');
  assert.doesNotMatch(textOf(summary), /Accesso consentito|Accesso negato/);
  assert.equal(article.querySelector('.request-context').textContent, 'Galleria · 120 persone');
});

test('a recorded timeline uses absolute offsets on one scale and keeps each phase inside its parent', function () {
  const ui = page(async function () { return empty; });
  const request = {
    id: 'bars', stato: 'completata', motore: 'confronto', tempo_complessivo_ms: 950,
    attesa_ms: 20, preparazione_ms: 30,
    risultati: [
      { motore: 'attuale', esito: 'aperto', tempi_ms: { totale: 500, cifratura: 40, server: 400, decifratura: 10, rete_e_server: 9000 } },
      { motore: 'a28', esito: 'negato', tempi_ms: { totale: 300, cifratura: 20, server: 250, decifratura: 15, rete_e_server: 8000 } },
    ],
    timeline: {
      elapsed_ms: 950,
      spans: [
        { id: 'job', parent_id: null, kind: 'job', start_ms: 0, end_ms: 950 },
        { id: 'queue', parent_id: 'job', kind: 'queue', start_ms: 0, end_ms: 20 },
        { id: 'prepare', parent_id: 'job', kind: 'prepare', start_ms: 20, end_ms: 50 },
        { id: 'attuale', parent_id: 'job', kind: 'engine', engine: 'attuale', start_ms: 50, end_ms: 570 },
        { id: 'attuale/setup', parent_id: 'attuale', kind: 'setup', start_ms: 50, end_ms: 65 },
        { id: 'attuale/encryption', parent_id: 'attuale', kind: 'encryption', start_ms: 70, end_ms: 110 },
        { id: 'attuale/fhe', parent_id: 'attuale', kind: 'fhe', start_ms: 115, end_ms: 535 },
        { id: 'attuale/decryption', parent_id: 'attuale', kind: 'decryption', start_ms: 540, end_ms: 550 },
        { id: 'a28', parent_id: 'job', kind: 'engine', engine: 'a28', start_ms: 600, end_ms: 920 },
        { id: 'a28/setup', parent_id: 'a28', kind: 'setup', start_ms: 600, end_ms: 610 },
        { id: 'a28/encryption', parent_id: 'a28', kind: 'encryption', start_ms: 610, end_ms: 630 },
        { id: 'a28/fhe', parent_id: 'a28', kind: 'fhe', start_ms: 640, end_ms: 890 },
        { id: 'a28/decryption', parent_id: 'a28', kind: 'decryption', start_ms: 900, end_ms: 915 },
      ],
    },
  };
  const details = ui.run(`requestDetails(${JSON.stringify(request)})`);
  const rows = details.querySelectorAll('.waterfall-row').filter(function (row) { return row.dataset.spanId; });
  assert.equal(rows.length, request.timeline.spans.length);
  for (const span of request.timeline.spans) {
    const row = rows.find(function (item) { return item.dataset.spanId === span.id; });
    const svg = row.querySelector('svg');
    const bar = svg.querySelector('rect');
    assert.equal(svg.namespaceURI, 'http://www.w3.org/2000/svg');
    assert.equal(svg.getAttribute('viewBox'), '0 0 950 16');
    assert.equal(Number(bar.getAttribute('x')), span.start_ms);
    assert.equal(Number(bar.getAttribute('width')), span.end_ms - span.start_ms);
    if (span.parent_id) {
      const parent = request.timeline.spans.find(function (item) { return item.id === span.parent_id; });
      assert.ok(Number(bar.getAttribute('x')) >= parent.start_ms);
      assert.ok(Number(bar.getAttribute('x')) + Number(bar.getAttribute('width')) <= parent.end_ms);
    }
    assert.deepEqual(svg.querySelectorAll('.timeline-grid').map(function (line) { return Number(line.getAttribute('x1')); }), [0, 237.5, 475, 712.5, 950]);
    for (const element of [row, svg, bar]) {
      assert.equal(element.getAttribute('style'), null);
      for (const offset of ['left', 'marginLeft', 'transform', 'translate']) assert.equal(element.style[offset], undefined);
    }
  }
  const groups = details.querySelectorAll('.waterfall-group');
  assert.deepEqual(groups.map(function (group) {
    return group.querySelector('.waterfall-children').querySelectorAll('.waterfall-label').map(function (label) { return label.textContent; });
  }), [['Preparazione motore', 'Cifratura', 'Servizio FHE', 'Decifratura'], ['Preparazione motore', 'Cifratura', 'Calcolo FHE', 'Decifratura']]);
  assert.ok(groups[0].querySelectorAll('.waterfall-row').every(function (row) { return row.matches('.timeline-attuale'); }));
  assert.ok(groups[1].querySelectorAll('.waterfall-row').every(function (row) { return row.matches('.timeline-a28'); }));
  assert.equal(groups[0].querySelector('.waterfall-measure').textContent, 'Solo calcolo FHE: 400 ms.');
  assert.equal(rows.find(function (row) { return row.dataset.spanId === 'attuale/fhe'; }).querySelector('.waterfall-value').textContent, '420 ms');
  assert.match(textOf(details), /trasferimento locale/);
  assert.match(textOf(details), /POST risponde 202/);
  assert.doesNotMatch(textOf(details), /9000|8000|rete_e_server/);
  assert.equal(details.querySelectorAll('progress').length, 0);
});

test('historical durations stay numeric without invented positions and keep missing values distinct from zero', function () {
  const ui = page(async function () { return empty; });
  const details = ui.run("requestDetails({id:'missing',stato:'elaborazione',motore:'confronto',attesa_ms:null,preparazione_ms:'0',risultati:[{motore:'attuale',esito:'aperto',tempi_ms:{totale:Infinity,cifratura:0,server:NaN,decifratura:-1}}]})");
  const rows = details.querySelectorAll('.waterfall-row');
  assert.equal(rows.length, 11);
  const known = rows.filter(function (row) { return row.querySelector('.waterfall-value').textContent !== '—'; });
  assert.equal(known.length, 1);
  assert.equal(known[0].querySelector('.waterfall-label').textContent, 'Cifratura');
  assert.equal(known[0].querySelector('.waterfall-value').textContent, '0 ms');
  assert.equal(details.querySelectorAll('svg').length, 0);
  assert.equal(details.querySelectorAll('progress').length, 0);
  assert.match(textOf(details), /solo le durate, senza gli istanti/);
  for (const row of rows.filter(function (item) { return item !== known[0]; })) {
    assert.equal(row.querySelector('.waterfall-value').textContent, '—');
    assert.equal(row.querySelector('.waterfall-track'), null);
  }
  ui.run("renderRequests([{id:'unknown-total',stato:'in_attesa',motore:'attuale'}])");
  let elapsed = ui.get('requests').querySelector('.request-duration');
  assert.equal(textOf(elapsed), '—');
  assert.equal(elapsed.querySelector('small'), null);
  ui.run("renderRequests([{id:'zero-total',stato:'completata',motore:'attuale',tempo_complessivo_ms:0}])");
  elapsed = ui.get('requests').querySelector('.request-duration');
  assert.equal(textOf(elapsed), '0 ms sul server');
  const fractional = ui.run("requestDetails({id:'fractional',stato:'completata',motore:'attuale',risultati:[{motore:'attuale',tempi_ms:{cifratura:0.026}}]})");
  const tiny = fractional.querySelectorAll('.waterfall-row').find(function (row) { return row.querySelector('.waterfall-label').textContent === 'Cifratura'; });
  assert.equal(tiny.querySelector('.waterfall-value').textContent, '0,026 ms');
  assert.equal(fractional.querySelector('svg'), null);
});

test('a failed comparison preserves the finished engine and never invents a result for the other engine', function () {
  const ui = page(async function () { return empty; });
  const request = {
    id: 'partial', stato: 'errore', motore: 'confronto', errore: 'A28: elaborazione interrotta.',
    risultati: [{ motore: 'attuale', esito: 'aperto', selected_name: 'Ada Lovelace', tempi_ms: { totale: 500, cifratura: 40, server: 400, decifratura: 10 } }],
  };
  ui.run(`renderRequests([${JSON.stringify(request)}])`);
  const article = ui.get('requests').querySelector('article');
  assert.equal(article.querySelector('.request-state').textContent, 'Errore nella verifica');
  assert.equal(article.querySelector('.request-error').textContent, request.errore);
  const groups = article.querySelectorAll('.waterfall-group');
  assert.equal(groups.length, 2);
  assert.equal(groups[0].querySelector('.waterfall-engine').querySelector('.waterfall-label').textContent, 'Attuale');
  assert.equal(groups[0].querySelector('.waterfall-result').textContent, 'Accesso consentito · Ada Lovelace');
  assert.deepEqual(groups[0].querySelectorAll('.waterfall-value').map(function (value) { return value.textContent; }), ['500 ms', '40 ms', '400 ms', '10 ms']);
  assert.equal(groups[1].querySelector('.waterfall-engine').querySelector('.waterfall-label').textContent, 'A28');
  assert.equal(groups[1].querySelector('.waterfall-result'), null);
  assert.equal(groups[1].querySelectorAll('progress').length, 0);
  assert.doesNotMatch(textOf(groups[1]), /Accesso consentito|Accesso negato|0 ms/);
  assert.equal(article.querySelectorAll('.waterfall-result').length, 1);
});

test('a live engine grows only from backend elapsed time and later receives its recorded phases', function () {
  const ui = page(async function () { return empty; });
  const request = {
    id: 'live', stato: 'elaborazione', motore: 'a28',
    timeline: { elapsed_ms: 100, spans: [
      { id: 'job', parent_id: null, kind: 'job', start_ms: 0, end_ms: null },
      { id: 'queue', parent_id: 'job', kind: 'queue', start_ms: 0, end_ms: 10 },
      { id: 'prepare', parent_id: 'job', kind: 'prepare', start_ms: 10, end_ms: 20 },
      { id: 'a28', parent_id: 'job', kind: 'engine', start_ms: 20, end_ms: null },
    ] },
  };
  ui.run(`renderRequests([${JSON.stringify(request)}])`);
  let details = ui.get('requests').querySelector('details');
  details.open = true;
  details.querySelector('summary').focus();
  let group = details.querySelector('.waterfall-group');
  assert.equal(group.querySelectorAll('.waterfall-row').length, 1);
  assert.equal(group.querySelector('.waterfall-result'), null);
  assert.equal(group.querySelector('.timeline-encryption'), null);
  assert.equal(group.querySelector('rect').getAttribute('x'), '20');
  assert.equal(group.querySelector('rect').getAttribute('width'), '80');
  assert.equal(group.querySelector('svg').getAttribute('viewBox'), '0 0 100 16');
  assert.match(textOf(group.querySelector('.waterfall-value')), /80 ms In corso/);
  assert.equal(textOf(details.querySelector('.request-duration')), '100 ms sul server');
  assert.equal(ui.timers.size, 0, 'no client clock extrapolates live intervals');
  request.timeline.elapsed_ms = 160;
  ui.run(`renderRequests([${JSON.stringify(request)}])`);
  details = ui.get('requests').querySelector('details');
  group = details.querySelector('.waterfall-group');
  assert.equal(details.open, true);
  assert.equal(ui.document.activeElement, details.querySelector('summary'));
  assert.equal(group.querySelector('rect').getAttribute('x'), '20');
  assert.equal(group.querySelector('rect').getAttribute('width'), '140');
  assert.equal(group.querySelector('svg').getAttribute('viewBox'), '0 0 160 16');
  assert.equal(textOf(details.querySelector('.request-duration')), '160 ms sul server');
  request.stato = 'completata';
  request.timeline.elapsed_ms = 170;
  request.timeline.spans[0].end_ms = 170;
  request.timeline.spans[3].end_ms = 150;
  request.timeline.spans.push(
    { id: 'a28/decryption', parent_id: 'a28', kind: 'decryption', start_ms: 140, end_ms: 140.026 },
    { id: 'a28/fhe', parent_id: 'a28', kind: 'fhe', start_ms: 65, end_ms: 130 },
    { id: 'a28/encryption', parent_id: 'a28', kind: 'encryption', start_ms: 30, end_ms: 60 },
  );
  request.risultati = [{ motore: 'a28', esito: 'negato', tempi_ms: { server: 65 } }];
  ui.run(`renderRequests([${JSON.stringify(request)}])`);
  details = ui.get('requests').querySelector('details');
  group = details.querySelector('.waterfall-group');
  assert.equal(group.querySelector('rect').getAttribute('width'), '130');
  assert.equal(group.querySelector('.timeline-active'), null);
  assert.deepEqual(group.querySelectorAll('.waterfall-row').map(function (row) { return row.dataset.spanId; }), ['a28', 'a28/encryption', 'a28/fhe', 'a28/decryption']);
  assert.equal(group.querySelector('.timeline-decryption').querySelector('.waterfall-value').textContent, '0,026 ms');
  assert.equal(group.querySelector('.waterfall-result').textContent, 'Accesso negato');
  assert.equal(details.open, true);
  assert.equal(ui.document.activeElement, details.querySelector('summary'));
});

test('zero-length and submillisecond spans keep their exact positions without fabricated minimum widths', function () {
  const ui = page(async function () { return empty; });
  const details = ui.run("requestDetails({motore:'attuale',stato:'completata',timeline:{elapsed_ms:0.026,spans:[{id:'job',parent_id:null,kind:'job',start_ms:0,end_ms:0.026},{id:'queue',parent_id:'job',kind:'queue',start_ms:0,end_ms:0},{id:'attuale',parent_id:'job',kind:'engine',start_ms:0,end_ms:0.026},{id:'attuale/encryption',parent_id:'attuale',kind:'encryption',start_ms:0,end_ms:0.026}]}})");
  const queue = details.querySelector('.timeline-queue');
  assert.equal(queue.querySelector('rect').getAttribute('width'), '0');
  assert.equal(queue.querySelector('.timeline-zero').getAttribute('x1'), '0');
  assert.equal(queue.querySelector('.waterfall-value').textContent, '0 ms');
  const tiny = details.querySelector('.timeline-encryption');
  assert.equal(tiny.querySelector('rect').getAttribute('width'), '0.026');
  assert.equal(tiny.querySelector('.waterfall-value').textContent, '0,026 ms');
  assert.equal(tiny.querySelector('svg').getAttribute('viewBox'), '0 0 0.026 16');
  assert.equal(details.querySelector('.timeline-decryption'), null, 'a phase not reported is not rendered as a zero-length phase');
});

test('failed timeline spans stay positioned while partial comparison results remain truthful', function () {
  const ui = page(async function () { return empty; });
  const request = {
    id: 'failed-trace', stato: 'errore', motore: 'confronto', errore: 'A28 interrotto.',
    risultati: [{ motore: 'attuale', esito: 'aperto', selected_name: 'Ada', tempi_ms: { server: 390 } }],
    timeline: { elapsed_ms: 610, spans: [
      { id: 'job', parent_id: null, kind: 'job', start_ms: 0, end_ms: 610, status: 'error' },
      { id: 'attuale', parent_id: 'job', kind: 'engine', start_ms: 0, end_ms: 500 },
      { id: 'attuale/fhe', parent_id: 'attuale', kind: 'fhe', start_ms: 10, end_ms: 410 },
      { id: 'a28', parent_id: 'job', kind: 'engine', start_ms: 500, end_ms: 600, status: 'error' },
      { id: 'a28/fhe', parent_id: 'a28', kind: 'fhe', start_ms: 505, end_ms: 600, status: 'error' },
    ] },
  };
  const details = ui.run(`requestDetails(${JSON.stringify(request)})`);
  const groups = details.querySelectorAll('.waterfall-group');
  assert.equal(groups[0].querySelector('.waterfall-result').textContent, 'Accesso consentito · Ada');
  assert.equal(groups[0].querySelector('.waterfall-measure').textContent, 'Solo calcolo FHE: 390 ms.');
  assert.equal(groups[1].querySelector('.waterfall-result'), null);
  assert.equal(groups[1].querySelector('rect').getAttribute('x'), '500');
  assert.equal(groups[1].querySelector('rect').getAttribute('width'), '100');
  assert.equal(groups[1].querySelectorAll('.timeline-error').length, 2);
  assert.match(textOf(groups[1]), /Interrotta/);
  assert.doesNotMatch(textOf(groups[1]), /In corso|Accesso negato|Accesso consentito/);
  assert.equal(details.querySelector('.request-error').textContent, 'A28 interrotto.');
});

test('invalid or disconnected spans cannot fabricate positions or discard an available result', function () {
  const ui = page(async function () { return empty; });
  const withoutRoot = ui.run("requestDetails({motore:'attuale',stato:'completata',risultati:[{motore:'attuale',esito:'negato',tempi_ms:{server:20}}],timeline:{elapsed_ms:100,spans:[{id:'orphan',parent_id:'missing',kind:'fhe',start_ms:10,end_ms:30}]}})");
  assert.equal(withoutRoot.querySelector('svg'), null);
  assert.equal(withoutRoot.querySelector('.waterfall-result').textContent, 'Accesso negato');
  const malformed = ui.run("requestDetails({motore:'attuale',stato:'completata',risultati:[{motore:'attuale',esito:'aperto',selected_name:'Ada'}],timeline:{elapsed_ms:100,spans:[{id:'job',parent_id:null,kind:'job',start_ms:0,end_ms:100},{id:'backwards',parent_id:'job',kind:'prepare',start_ms:50,end_ms:40},{id:'invalid',parent_id:'job',kind:'queue',start_ms:0,end_ms:NaN},{id:'orphan',parent_id:'missing',kind:'fhe',start_ms:10,end_ms:30},{id:'future',parent_id:'job',kind:'engine',start_ms:150,end_ms:null}]}})");
  assert.equal(malformed.querySelectorAll('svg').length, 1);
  assert.equal(malformed.querySelector('.timeline-job').querySelector('rect').getAttribute('width'), '100');
  assert.equal(malformed.querySelector('.waterfall-result').textContent, 'Attuale: Accesso consentito · Ada');
});

test('session renewal clears local photos and ignores a former session response', async function () {
  const response = deferred();
  const ui = page(function () { return response.promise; });
  ui.run("updateSession('2026-09-20T22:00:00Z')");
  ui.get('probe-files').files = [{ name: 'photo.jpg' }];
  await ui.get('probe-files').emit('change');
  assert.equal(ui.run('probeSource.hasInput'), true);
  const loading = ui.run('loadGallery()');
  ui.run("updateSession('2026-09-20T23:00:00Z')");
  response.resolve({ iscritti: [{ id: 'expired', nome: 'Expired', soglia: 273 }] });
  await loading;
  assert.equal(ui.run('probeSource.hasInput'), false);
  assert.equal(ui.run('state.people.length'), 0);
});

test('late camera permission after closing stops the stream and keeps preview closed', async function () {
  const permission = deferred();
  const track = { readyState: 'live', stop() { this.readyState = 'ended'; } };
  const stream = { getTracks() { return [track]; }, getVideoTracks() { return [track]; } };
  const ui = page(async function () { return empty; }, { media: function () { return permission.promise; } });
  const starting = ui.get('probe-start').emit('click');
  await settle();
  await ui.get('probe-stop').emit('click');
  permission.resolve(stream);
  await starting;
  assert.equal(track.readyState, 'ended');
  assert.equal(ui.get('probe-box').hidden, true);
  assert.equal(ui.run('probeSource.hasInput'), false);
});

test('returning from back-forward cache ignores the previous status fetch', async function () {
  const old = deferred();
  const fresh = deferred();
  let calls = 0;
  const ui = page(function (path) {
    if (path !== '/api/stato') return Promise.resolve(empty);
    return ++calls === 1 ? old.promise : fresh.promise;
  }, { start: true });
  ui.windowListeners.pagehide();
  ui.windowListeners.pageshow({ persisted: true });
  fresh.resolve(readyStatus);
  await settle();
  old.resolve({ pronto: false, motori: [] });
  await settle();
  assert.equal(ui.run('state.connected'), true);
  assert.equal(ui.run('state.ready'), true);
  assert.equal(ui.streams.length, 1);
  assert.equal(ui.streams[0].closed, false);
  assert.equal(ui.timers.size, 0);
});

test('example photo selection is labelled as the enrollment photo and never starts a request', async function () {
  const calls = [];
  const images = [];
  let uploads = 0;
  const ui = page(async function (path) { calls.push(path); return empty; }, {
    readPhotos: async function () { uploads += 1; return ['data:image/jpeg;base64,upload']; },
    fetch: async function (url, options) {
      images.push({ url, options });
      return { ok: true, blob: async function () { return jpegBlob; } };
    },
  });
  ui.run('state.connected = true');
  await ui.run("useExample({id:'grace',nome:'Grace Hopper',esempio:true,foto_url:'/api/foto/grace'})");
  assert.equal(images.length, 1);
  assert.equal(images[0].url, 'http://127.0.0.1:8010/api/foto/grace');
  assert.equal(images[0].options.credentials, 'same-origin');
  assert.equal(ui.run('probeSource.hasInput'), true);
  const frames = await ui.run('probeSource.getFrames()');
  assert.equal(frames.length, 1);
  assert.equal(frames[0], `data:image/jpeg;base64,${jpegBytes.toString('base64')}`);
  assert.deepEqual(Buffer.from(frames[0].split(',')[1], 'base64'), jpegBytes);
  assert.equal(uploads, 0, 'gallery JPEGs must never enter the canvas upload path');
  assert.match(ui.get('probe-hint').textContent, /Stessa foto d’iscrizione · Grace Hopper/);
  assert.deepEqual(calls, []);
  assert.equal(ui.document.activeElement, ui.get('probe-title'));
  ui.get('probe-files').files = [{ name: 'different.jpg' }];
  await ui.get('probe-files').emit('change');
  assert.equal(uploads, 1, 'ordinary uploads still use readPhotos');
  assert.doesNotMatch(ui.get('probe-hint').textContent, /Stessa foto d’iscrizione/);
});

test('example selection rejects external photo URLs and entries not marked as examples', async function () {
  const ui = page(async function () { return empty; });
  ui.run('state.connected = true');
  await ui.run("useExample({nome:'Example',esempio:true,foto_url:'https://example.org/api/foto/one'})");
  assert.match(ui.get('probe-source-error').textContent, /non è disponibile/);
  assert.equal(ui.run('probeSource.hasInput'), false);
  await ui.run("useExample({nome:'Private',foto_url:'/api/foto/private'})");
  assert.equal(ui.run('probeSource.hasInput'), false);
});

test('session renewal prevents an old example download from restoring a photo', async function () {
  const downloaded = deferred();
  const ui = page(async function () { return empty; }, { fetch: function () { return downloaded.promise; } });
  ui.run("state.connected = true; updateSession('2026-09-20T22:00:00Z')");
  const selecting = ui.run("useExample({nome:'Grace Hopper',esempio:true,foto_url:'/api/foto/grace'})");
  ui.run("updateSession('2026-09-20T23:00:00Z')");
  downloaded.resolve({ ok: true, blob: async function () { return jpegBlob; } });
  await selecting;
  assert.equal(ui.run('probeSource.hasInput'), false);
  assert.doesNotMatch(ui.get('probe-hint').textContent, /Grace Hopper/);
});

test('changing or clearing the probe photo detaches previous results while retaining history', async function () {
  const ui = page(async function () { return empty; });
  const request = { id: 'old-photo', stato: 'completata', motore: 'attuale',
    risultati: [{ esito: 'aperto', selected_name: 'Ada' }] };
  function displayResult() {
    ui.run(`state.latestId = 'old-photo'; state.latestSignature = null; applyRequests({richieste:[${JSON.stringify(request)}]})`);
    assert.equal(ui.get('probe-result').hidden, false);
  }
  displayResult();
  ui.get('probe-files').files = [{ name: 'another-person.jpg' }];
  await ui.get('probe-files').emit('change');
  assert.equal(ui.get('probe-result').hidden, true);
  assert.equal(ui.run('state.latestId'), null);
  ui.run(`applyRequests({richieste:[${JSON.stringify(request)}]})`);
  assert.equal(ui.get('probe-result').hidden, true, 'later events cannot attach the old result to new photos');
  assert.equal(ui.run('state.requests.length'), 1);
  displayResult();
  await ui.get('probe-clear').emit('click');
  assert.equal(ui.get('probe-result').hidden, true);
  assert.equal(ui.run('probeSource.hasInput'), false);
});

test('a failed photo replacement preserves the previous input and its result', async function () {
  let reads = 0;
  const ui = page(async function () { return empty; }, {
    readPhotos: async function () {
      if (++reads > 1) throw new Error('Foto non valida.');
      return ['data:image/jpeg;base64,original'];
    },
  });
  ui.get('probe-files').files = [{ name: 'original.jpg' }];
  await ui.get('probe-files').emit('change');
  ui.run("state.latestId='old';state.requests=[{id:'old',stato:'completata',motore:'attuale',risultati:[{esito:'aperto',selected_name:'Ada'}]}];renderLatest()");
  ui.get('probe-files').files = [{ name: 'invalid.jpg' }];
  await ui.get('probe-files').emit('change');
  assert.equal(ui.get('probe-result').hidden, false);
  assert.equal(ui.run('state.latestId'), 'old');
  assert.equal((await ui.run('probeSource.getFrames()'))[0], 'data:image/jpeg;base64,original');
  assert.match(ui.get('probe-source-error').textContent, /Foto non valida/);
});

test('a capture from an expired session cannot restore frames or stop a newly opened camera', async function () {
  for (const prefix of ['probe', 'person']) {
    const tracks = [];
    const ui = page(async function () { return empty; }, { media: async function () {
      const track = { readyState: 'live', stop() { this.readyState = 'ended'; } };
      tracks.push(track);
      return { getTracks() { return [track]; }, getVideoTracks() { return [track]; } };
    } });
    ui.run("globalThis.FRAME_COUNT=3;globalThis.encodeImage=()=> 'data:image/jpeg;base64,captured';globalThis.delay=ms=>new Promise(resolve=>setTimeout(resolve,ms))");
    ui.get(`${prefix}-camera`).videoWidth = 640;
    ui.get(`${prefix}-camera`).videoHeight = 480;
    await ui.get(`${prefix}-start`).emit('click');
    const capture = ui.run(`${prefix}Source.getFrames()`).then(
      function () { return null; }, function (error) { return error; });
    ui.run('clearSession()');
    await ui.get(`${prefix}-start`).emit('click');
    await ui.fireTimer(220);
    await ui.fireTimer(220);
    assert.match((await capture)?.message || '', /Acquisizione annullata/);
    assert.equal(tracks[1].readyState, 'live');
    assert.equal(ui.get(`${prefix}-previews`).children.length, 0);
    await ui.get(`${prefix}-stop`).emit('click');
    assert.equal(ui.run(`${prefix}Source.hasInput`), false);
  }
});

test('opening a new probe camera clears the result associated with the old input', async function () {
  const track = { readyState: 'live', stop() { this.readyState = 'ended'; } };
  const ui = page(async function () { return empty; }, { media: async function () {
    return { getTracks() { return [track]; }, getVideoTracks() { return [track]; } };
  } });
  ui.run("state.latestId='old';state.requests=[{id:'old',stato:'completata',motore:'attuale',risultati:[{esito:'aperto',selected_name:'Ada'}]}];renderLatest()");
  await ui.get('probe-start').emit('click');
  assert.equal(ui.get('probe-result').hidden, true);
  assert.equal(ui.run('state.latestId'), null);
  assert.equal(ui.run('probeSource.hasInput'), true);
});

test('gallery JPEG reader rejects other MIME types, empty files and oversized files before reading', function () {
  const ui = page(async function () { return empty; });
  for (const blob of [
    { type: 'image/png', size: 20 },
    { type: 'image/jpeg', size: 0 },
    { type: 'image/jpeg', size: 4 * 1024 * 1024 + 1 },
  ]) {
    assert.throws(function () { ui.run(`readGalleryJPEG(${JSON.stringify(blob)})`); }, /JPEG.*4 MiB/);
  }
});

test('credit links allow only absolute HTTP or HTTPS without embedded credentials', function () {
  const ui = page(async function () { return empty; });
  for (const url of ['javascript:alert(1)', 'data:text/html,hello', '/relative', 'https://user:password@example.org/photo']) {
    assert.equal(ui.run(`safeCreditURL(${JSON.stringify(url)})`), null);
  }
  assert.equal(ui.run("safeCreditURL('https://example.org/photo')"), 'https://example.org/photo');
  const link = ui.run("creditLink('Fonte', 'https://example.org/photo')");
  assert.equal(link.rel, 'noopener noreferrer');
  assert.equal(link.target, '_blank');
});

test('gallery notes and example actions are optional, and credits preserve expansion and focus', function () {
  const ui = page(async function () { return empty; });
  const sample = {
    id: 'grace', nome: 'Grace Hopper', soglia: 273, esempio: true,
    foto_url: '/api/foto/grace', nota: 'Il primo bug non era cifrato.',
    crediti: { autore: 'Autore', licenza: 'Licenza', url: 'https://example.org/photo', licenza_url: 'https://example.org/license' },
  };
  ui.run(`renderGallery(${JSON.stringify([sample, { id: 'private', nome: 'Private', soglia: 273 }])})`);
  const actions = ui.get('gallery').querySelectorAll('button').filter(function (button) { return button.dataset.exampleAction === 'true'; });
  assert.equal(actions.length, 1);
  assert.equal(actions[0].getAttribute('aria-label'), 'Usa Grace Hopper per una prova');
  assert.equal(ui.get('photo-credits').hidden, false);
  ui.get('photo-credits').open = true;
  const link = ui.get('photo-credits-list').querySelector('a');
  link.focus();
  sample.soglia = 250;
  ui.run(`renderGallery(${JSON.stringify([sample])})`);
  assert.equal(ui.get('photo-credits').open, true);
  assert.equal(ui.document.activeElement, ui.get('photo-credits-list').querySelector('a'));
});

function largeGallery() {
  return Array.from({ length: 120 }, function (_, index) {
    return {
      id: `person-${index}`, nome: `Person ${String(index).padStart(3, '0')}`, soglia: 273,
      esempio: true, foto_url: `/api/foto/person-${index}`,
      nota: index === 119 ? 'Luke Skywalker' : 'Scienza',
      crediti: { autore: 'Autore', url: `https://example.org/photo-${index}` },
    };
  });
}

test('search and progressive reveal keep the full 120-person gallery and every credit', async function () {
  const people = largeGallery();
  const original = JSON.stringify(people);
  const calls = [];
  const ui = page(async function (path) { calls.push(path); return { iscritti: people, totale: people.length }; });
  await ui.run('loadGallery()');
  assert.equal(ui.get('gallery').children.length, 12);
  assert.equal(ui.get('gallery-count').textContent, '120');
  assert.equal(ui.get('gallery-shown').textContent, 'Mostrate 12 di 120');
  assert.equal(ui.get('photo-credits-list').children.length, 120);
  await ui.get('gallery-more').emit('click');
  assert.equal(ui.get('gallery').children.length, 24);
  assert.equal(ui.document.activeElement.closest('[data-person-id]').dataset.personId, 'person-12');
  ui.get('gallery-search').value = '  SKYwalkér  ';
  ui.get('gallery-search').focus();
  await ui.get('gallery-search').emit('input');
  assert.equal(ui.get('gallery').children.length, 1);
  assert.equal(ui.get('gallery').children[0].dataset.personId, 'person-119');
  assert.equal(ui.get('gallery-count').textContent, '1 di 120');
  assert.equal(ui.get('gallery-more').hidden, true);
  assert.equal(ui.document.activeElement, ui.get('gallery-search'));
  assert.equal(ui.get('photo-credits-list').children.length, 120);
  ui.get('gallery-search').value = '';
  await ui.get('gallery-search').emit('input');
  assert.equal(ui.get('gallery').children.length, 12);
  for (let batch = 1; batch < 10; batch += 1) await ui.get('gallery-more').emit('click');
  assert.equal(ui.get('gallery').children.length, 120);
  assert.equal(ui.get('gallery-more').hidden, true);
  assert.equal(ui.document.activeElement.closest('[data-person-id]').dataset.personId, 'person-108');
  assert.equal(ui.run('JSON.stringify(state.people)'), original);
  assert.equal(JSON.stringify(people), original);
  assert.deepEqual(calls, ['/api/galleria']);
});

test('entry actions work after filtering and an empty visual result never narrows an access request', async function () {
  const people = largeGallery();
  const submitted = [];
  const photos = [];
  const ui = page(async function (path, options) {
    if (path === '/api/galleria') return { iscritti: people, totale: 120 };
    if (path === '/api/accesso') { submitted.push(options.body); return { richiesta_id: 'full-gallery' }; }
    if (path === '/api/richieste') return { richieste: [{ id: 'full-gallery', stato: 'in_attesa', motore: 'attuale', iscritti: 120 }] };
    throw new Error(`Unexpected API ${path}`);
  }, {
    fetch: async function (url) { photos.push(url); return { ok: true, blob: async function () { return jpegBlob; } }; },
  });
  ui.run("state.connected = true; state.ready = true; state.engines = [{id:'attuale',pronto:true}]");
  await ui.run('loadGallery()');
  ui.get('gallery-search').value = 'skywalker';
  await ui.get('gallery-search').emit('input');
  const row = ui.get('gallery').children[0];
  const edit = row.querySelectorAll('button').find(function (button) { return button.dataset.personAction === 'edit'; });
  await edit.emit('click');
  assert.equal(ui.get('person-name').value, 'Person 119');
  assert.equal(ui.run('state.editingId'), 'person-119');
  ui.run('closePerson()');
  const use = row.querySelectorAll('button').find(function (button) { return button.dataset.exampleAction === 'true'; });
  await use.emit('click');
  assert.deepEqual(photos, ['http://127.0.0.1:8010/api/foto/person-119']);
  assert.equal(submitted.length, 0);
  ui.get('gallery-search').value = 'no-match';
  await ui.get('gallery-search').emit('input');
  assert.equal(ui.get('gallery').children.length, 0);
  assert.equal(ui.get('gallery-count').textContent, '0 di 120');
  assert.equal(ui.get('submit-probe').disabled, false);
  await ui.run('submitProbe()');
  assert.equal(submitted.length, 1);
  assert.deepEqual(Object.keys(submitted[0]).sort(), ['frames', 'motore']);
  assert.equal(submitted[0].motore, 'attuale');
  assert.equal(ui.run('state.people.length'), 120);
  const details = ui.run("requestDetails({id:'full-gallery',stato:'in_attesa',iscritti:120})");
  assert.ok(details.children.some(function (child) { return child.textContent === 'Galleria · 120 persone'; }));
});

test('gallery updates preserve the search, expanded count and edited action focus while retaining new entries', async function () {
  let people = largeGallery();
  const ui = page(async function () { return { iscritti: people, totale: people.length }; });
  await ui.run('loadGallery()');
  ui.get('gallery-search').value = 'person';
  await ui.get('gallery-search').emit('input');
  await ui.get('gallery-more').emit('click');
  const action = ui.get('gallery').children[18].querySelectorAll('button').find(function (button) { return button.dataset.personAction === 'edit'; });
  action.focus();
  people = people.map(function (person, index) { return index === 18 ? { ...person, nome: 'Person 018 updated', soglia: 250 } : person; });
  people.push({ id: 'new', nome: 'New Researcher', soglia: 273 });
  await ui.run('loadGallery()');
  assert.equal(ui.get('gallery-search').value, 'person');
  assert.equal(ui.get('gallery').children.length, 24);
  assert.equal(ui.get('gallery-count').textContent, '120 di 121');
  assert.equal(ui.document.activeElement.getAttribute('aria-label'), 'Modifica Person 018 updated');
  assert.equal(ui.document.activeElement.closest('[data-person-id]').dataset.personId, 'person-18');
  assert.equal(ui.run('state.people.length'), 121);
  ui.get('gallery-search').value = 'new researcher';
  await ui.get('gallery-search').emit('input');
  assert.equal(ui.get('gallery').children.length, 1);
  assert.equal(ui.get('gallery').children[0].dataset.personId, 'new');
  const remove = ui.get('gallery').children[0].querySelectorAll('button').find(function (button) { return button.dataset.personAction === 'trash'; });
  await remove.emit('click');
  assert.equal(ui.run('state.deletingId'), 'new');
});
