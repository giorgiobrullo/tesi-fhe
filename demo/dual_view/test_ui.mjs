import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = (name) => readFileSync(new URL(`static/${name}.js`, import.meta.url), 'utf8');
const settle = () => new Promise((resolve) => setImmediate(resolve));
function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

// Only the DOM operations used by these asynchronous paths are needed here.
function page(name, api, start = true) {
  const elements = new Map();
  const listeners = {};
  const timers = new Map();
  let nextTimer = 0;
  const element = () => ({
    hidden: false, value: '', textContent: '', children: [], dataset: {}, style: {},
    setAttribute() {}, replaceChildren() {}, append() {}, addEventListener() {},
    close() {}, reportValidity() { return true; },
  });
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  const context = vm.createContext({
    api, console, Date, Number, String, Set, JSON, Promise,
    document: { getElementById: get, createDocumentFragment: element },
    window: { addEventListener(event, callback) { listeners[event] = callback; } },
    Camera: class { get active() { return false; } stop() {} },
    mountIcons() {}, duration() { return 'n/d'; },
    setConnection(node, ready) { node.ready = ready; },
    setTimeout(callback) { timers.set(++nextTimer, callback); return nextTimer; },
    clearTimeout(id) { timers.delete(id); },
  });
  let script = source(name).replace(/^import .*;\n/, '');
  if (!start) script = script.split("byId('add-person').addEventListener")[0];
  vm.runInContext(script, context);
  return { run: (code) => vm.runInContext(code, context), get, listeners, timers };
}

for (const mutation of ['edit', 'delete']) {
  test(`a completed ${mutation} refreshes past an older pending gallery response`, async () => {
    const oldRead = deferred();
    const freshRead = deferred();
    let reads = 0;
    const ui = page('server', (path) => {
      if (path === '/api/galleria') return ++reads === 1 ? oldRead.promise : freshRead.promise;
      return Promise.resolve({ ok: true });
    }, false);
    ui.run(`
      renderGallery = function () {};
      people = [{ id: 'person', nome: 'Before', soglia: 273 }];
      galleryLoaded = true;
      gallerySignature = JSON.stringify(people);
      editingPerson = people[0];
      deletingPerson = people[0];
      byId('person-name').value = 'After';
      byId('person-threshold').value = '-1';
    `);
    const initialLoad = ui.run('loadGallery()');
    const change = ui.run(mutation === 'edit'
      ? 'savePerson({ preventDefault() {} })' : 'deletePerson()');
    await settle();
    oldRead.resolve({ iscritti: [{ id: 'person', nome: 'Stale', soglia: 273 }] });
    await settle();
    assert.equal(reads, 2, 'the mutation must queue a fresh read');
    assert.equal(ui.run('people[0].nome'), 'Before', 'the invalidated response must not render');
    const current = mutation === 'edit' ? [{ id: 'person', nome: 'After', soglia: -1 }] : [];
    freshRead.resolve({ iscritti: current });
    await Promise.all([initialLoad, change]);
    assert.equal(ui.run('JSON.stringify(people)'), JSON.stringify(current));
  });
}

for (const name of ['client', 'server']) {
  test(`${name} ignores a stale poll after returning from the back-forward cache`, async () => {
    const pending = [];
    const ui = page(name, (path) => {
      if (path === '/api/galleria') return Promise.resolve({ iscritti: [] });
      const request = { path, ...deferred() };
      pending.push(request);
      return request.promise;
    });
    ui.listeners.pagehide();
    const oldCount = pending.length;
    ui.listeners.pageshow({ persisted: true });
    const status = (ready) => ({ pronto: ready, iscritti: 0, richieste: 0 });
    const finish = (requests, ready) => requests.forEach((request) => request.resolve(
      request.path === '/api/stato' ? status(ready) : { richieste: [], totale: 0 },
    ));
    finish(pending.slice(oldCount), true);
    await settle();
    finish(pending.slice(0, oldCount), false);
    await settle();
    assert.equal(ui.get('connection').ready, true, 'the stale response must not replace current state');
    assert.equal(ui.timers.size, 1, 'there must be one polling loop after restoration');
  });
}

function camera(getUserMedia, play = async () => {}) {
  const video = { srcObject: null, play };
  const context = vm.createContext({ navigator: { mediaDevices: { getUserMedia } }, video });
  vm.runInContext(source('shared').replace(/^export /gm, ''), context);
  return { camera: vm.runInContext('new Camera(video)', context), video };
}

function stream() {
  const track = { readyState: 'live', stop() { this.readyState = 'ended'; } };
  return { track, getTracks() { return [track]; }, getVideoTracks() { return [track]; } };
}

test('closing while camera permission is pending stops the late stream', async () => {
  const permission = deferred();
  const media = stream();
  const ui = camera(() => permission.promise);
  const started = ui.camera.start();
  ui.camera.stop();
  permission.resolve(media);
  assert.equal(await started, false);
  assert.equal(media.track.readyState, 'ended');
  assert.equal(ui.video.srcObject, null);
});

test('closing while video playback starts cannot reactivate the camera UI', async () => {
  const playback = deferred();
  const media = stream();
  const ui = camera(async () => media, () => playback.promise);
  const started = ui.camera.start();
  await settle();
  ui.camera.stop();
  playback.resolve();
  assert.equal(await started, false);
  assert.equal(ui.camera.active, false);
  assert.equal(media.track.readyState, 'ended');
  assert.equal(ui.video.srcObject, null);
});

test('denied camera permission leaves the upload fallback available', async () => {
  const ui = camera(async () => { throw Object.assign(new Error(), { name: 'NotAllowedError' }); });
  await assert.rejects(ui.camera.start(), /Consenti l’uso della fotocamera.*carica una foto/);
  assert.equal(ui.camera.active, false);
  assert.equal(ui.video.srcObject, null);
});
