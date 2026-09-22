import { api, Camera, duration, galleryPhotoURL, icon, mountIcons, readPhotos, renderPreviews } from '/shared/shared.js';

const $ = function (id) { return document.getElementById(id); };
const GALLERY_PAGE_SIZE = 12;
const RECONNECT_DELAY = 1000;
const MAX_RECONNECT_DELAY = 30000;
const STATUS = {
  in_attesa: 'In attesa',
  preparazione: 'Preparazione delle foto',
  cifratura: 'Cifratura',
  elaborazione: 'Elaborazione FHE',
  decifratura: 'Decifratura',
  completata: 'Completata',
  errore: 'Errore nella verifica',
};
const state = {
  connected: false, ready: false, preparationError: null, engines: [], people: [], requests: [],
  submitting: false, personBusy: false, deleteBusy: false,
  editingId: null, deletingId: null, latestId: null,
  galleryVersion: 0, gallerySignature: null, requestSignature: null, latestSignature: null,
  galleryQuery: '', galleryVisible: GALLERY_PAGE_SIZE, creditsSignature: null,
  sessionExpiry: null, sessionVersion: 0, statusVersion: 0,
  leaving: false, connectionGeneration: 0, stream: null, reconnectTimer: null,
  reconnectDelay: RECONNECT_DELAY, toastTimer: null,
};

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function showError(id, error) {
  const element = $(id);
  element.textContent = error?.message || error || '';
  element.hidden = !element.textContent;
}

function toast(message) {
  clearTimeout(state.toastTimer);
  $('toast').textContent = message;
  $('toast').hidden = false;
  state.toastTimer = setTimeout(function () { $('toast').hidden = true; }, 3200);
}

function engineName(id) {
  if (id === 'attuale') return 'Attuale';
  if (id === 'a28') return 'A28';
  if (id === 'confronto') return 'Confronto';
  return 'Motore non indicato';
}

function readGalleryJPEG(blob) {
  if (blob.type !== 'image/jpeg' || !Number.isSafeInteger(blob.size) || blob.size < 1 || blob.size > 4 * 1024 * 1024) {
    throw new Error('La foto d’esempio deve essere un JPEG non vuoto, fino a 4 MiB.');
  }
  return new Promise(function (resolve, reject) {
    const reader = new FileReader();
    const failed = function () { reject(new Error('Non è stato possibile leggere la foto d’esempio.')); };
    reader.onload = function () {
      if (typeof reader.result !== 'string' || !reader.result.startsWith('data:image/jpeg;base64,')) {
        failed();
        return;
      }
      resolve(reader.result);
    };
    reader.onerror = failed;
    reader.onabort = failed;
    reader.readAsDataURL(blob);
  });
}

function updateControls() {
  const engine = state.engines.find(function (item) { return item.id === 'attuale'; });
  const ready = state.connected && state.ready && engine?.pronto === true;
  $('submit-probe').disabled = !ready || !state.people.length || !probeSource.hasInput || probeSource.loading || state.submitting;
  $('add-person').disabled = !ready || state.personBusy;
  for (const button of $('gallery').querySelectorAll('button')) {
    if (button.dataset.exampleAction === 'true') button.disabled = !state.connected || state.submitting || probeSource.loading;
  }
  if (!state.connected) {
    $('engine-readiness').textContent = 'In attesa del collegamento al servizio.';
  } else if (state.preparationError) {
    $('engine-readiness').textContent = state.preparationError;
  } else if (engine?.errore) {
    $('engine-readiness').textContent = engine.errore;
  } else if (!ready) {
    $('engine-readiness').textContent = 'Preparazione della verifica…';
  } else if (!state.people.length) {
    $('engine-readiness').textContent = 'Aggiungi una persona alla galleria.';
  } else {
    $('engine-readiness').textContent = 'Pronto per la verifica.';
  }
  if ($('person-dialog').open) {
    $('save-person').disabled = state.personBusy || personSource.loading || (!state.editingId && !personSource.hasInput);
  }
}

function makePhotoSource(prefix, beforeCamera, onChange = function () {}) {
  const camera = new Camera($(`${prefix}-camera`));
  let frames = [];
  let loading = false;
  let locked = false;
  let generation = 0;
  let photoDescription = '';

  function refresh() {
    $(`${prefix}-start`).disabled = locked || loading || camera.active;
    $(`${prefix}-choose`).disabled = locked || loading;
    $(`${prefix}-clear`).disabled = locked || loading;
    $(`${prefix}-stop`).disabled = locked;
    $(`${prefix}-clear`).hidden = !frames.length;
    $(`${prefix}-previews`).hidden = !frames.length || camera.active;
    let hint = 'Da una a tre foto. JPG, PNG o WebP.';
    if (loading) hint = 'Preparazione dell’anteprima…';
    else if (camera.active) hint = 'Tre scatti saranno acquisiti alla conferma.';
    else if (frames.length) hint = `${frames.length} ${frames.length === 1 ? 'foto selezionata' : 'foto selezionate'}.`;
    if (frames.length && !loading && !camera.active && photoDescription) hint = photoDescription;
    $(`${prefix}-hint`).textContent = hint;
    updateControls();
  }

  function stopCamera() {
    generation += 1;
    loading = false;
    camera.stop();
    $(`${prefix}-box`).hidden = true;
    $(`${prefix}-camera`).hidden = true;
    refresh();
  }

  function reset() {
    frames = [];
    photoDescription = '';
    onChange();
    $(`${prefix}-files`).value = '';
    renderPreviews($(`${prefix}-previews`), frames);
    showError(`${prefix}-source-error`, null);
    stopCamera();
  }

  async function startCamera() {
    if (locked || loading) return;
    beforeCamera();
    const current = ++generation;
    loading = true;
    showError(`${prefix}-source-error`, null);
    $(`${prefix}-box`).hidden = false;
    $(`${prefix}-camera-status`).hidden = false;
    $(`${prefix}-camera-status`).textContent = 'Apertura della fotocamera…';
    refresh();
    try {
      const started = await camera.start();
      if (current !== generation || state.leaving) return;
      if (!started) {
        $(`${prefix}-box`).hidden = true;
        return;
      }
      frames = [];
      photoDescription = '';
      onChange();
      renderPreviews($(`${prefix}-previews`), frames);
      $(`${prefix}-files`).value = '';
      $(`${prefix}-camera`).hidden = false;
      $(`${prefix}-camera-status`).hidden = true;
    } catch (error) {
      if (current !== generation) return;
      $(`${prefix}-box`).hidden = true;
      showError(`${prefix}-source-error`, error);
    } finally {
      if (current === generation) { loading = false; refresh(); }
    }
  }

  async function loadPhotos(read, description = '') {
    if (locked || loading) return false;
    const current = ++generation;
    loading = true;
    showError(`${prefix}-source-error`, null);
    refresh();
    try {
      const photos = await read();
      if (current !== generation || state.leaving) return false;
      camera.stop();
      frames = photos;
      photoDescription = description;
      onChange();
      $(`${prefix}-box`).hidden = true;
      renderPreviews($(`${prefix}-previews`), frames);
      return true;
    } catch (error) {
      if (current === generation) showError(`${prefix}-source-error`, error);
    } finally {
      if (current === generation) { loading = false; refresh(); }
    }
    return false;
  }

  async function loadFiles() {
    const files = Array.from($(`${prefix}-files`).files || []);
    $(`${prefix}-files`).value = '';
    if (!files.length) return;
    await loadPhotos(function () { return readPhotos(files); });
  }

  $(`${prefix}-start`).addEventListener('click', startCamera);
  $(`${prefix}-stop`).addEventListener('click', stopCamera);
  $(`${prefix}-choose`).addEventListener('click', function () { $(`${prefix}-files`).click(); });
  $(`${prefix}-files`).addEventListener('change', loadFiles);
  $(`${prefix}-clear`).addEventListener('click', reset);
  return {
    get hasInput() { return Boolean(frames.length || camera.active); },
    get loading() { return loading; },
    setLocked(value) { locked = value; refresh(); },
    reset,
    stopCamera,
    async loadGalleryPhoto(url, name) {
      return loadPhotos(async function () {
        const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store' });
        if (!response.ok) throw new Error('La foto d’esempio non è disponibile. Aggiorna la galleria e riprova.');
        return [await readGalleryJPEG(await response.blob())];
      }, `Stessa foto d’iscrizione · ${name}. Per provare il riconoscimento su una foto diversa, caricane un’altra.`);
    },
    async getFrames(onProgress) {
      if (camera.active) {
        const current = generation;
        const captured = await camera.capture(function (count, total) {
          if (current === generation && !state.leaving) onProgress?.(count, total);
        });
        if (current !== generation || state.leaving) throw new Error('Acquisizione annullata. Seleziona di nuovo le foto.');
        frames = captured;
        photoDescription = '';
        renderPreviews($(`${prefix}-previews`), frames);
        stopCamera();
      }
      if (!frames.length) throw new Error('Scegli una foto oppure attiva la fotocamera.');
      return frames.slice();
    },
  };
}

const probeSource = makePhotoSource('probe', function () { personSource.stopCamera(); }, clearProbeResult);
const personSource = makePhotoSource('person', function () { probeSource.stopCamera(); });

function clearProbeResult() {
  state.latestId = null;
  state.latestSignature = null;
  $('probe-progress').hidden = true;
  $('probe-result').hidden = true;
  $('probe-result').replaceChildren();
  showError('probe-error', null);
}

function personAction(label, symbol, action) {
  const button = node('button', 'icon-button');
  button.type = 'button';
  button.setAttribute('aria-label', label);
  button.dataset.personAction = symbol;
  button.title = label;
  button.append(icon(symbol));
  button.addEventListener('click', action);
  return button;
}

function safeCreditURL(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    return url.href;
  } catch { return null; }
}

function creditLink(label, value) {
  const url = safeCreditURL(value);
  if (!url) return node('span', '', label);
  const link = node('a', '', label);
  link.href = url;
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  return link;
}

function renderCredits(people) {
  const signature = JSON.stringify(people.map(function (person) { return [person.id, person.nome, person.crediti]; }));
  if (signature === state.creditsSignature) return;
  state.creditsSignature = signature;
  const focused = document.activeElement;
  const focusId = focused?.closest('[data-credit-id]')?.dataset.creditId;
  const focusURL = focused?.href;
  const rows = [];
  for (const person of people) {
    const credit = person.crediti;
    if (!credit || typeof credit !== 'object') continue;
    const author = typeof credit.autore === 'string' ? credit.autore : '';
    const license = typeof credit.licenza === 'string' ? credit.licenza : '';
    const source = safeCreditURL(credit.url);
    if (!author && !license && !source) continue;
    const row = node('li');
    row.dataset.creditId = String(person.id);
    row.append(node('span', '', `${person.nome}${author ? ` · ${author}` : ''}`));
    if (source) row.append(node('span', '', ' · '), creditLink('Fonte', source));
    if (license) row.append(node('span', '', ' · '), creditLink(license, credit.licenza_url));
    rows.push(row);
  }
  $('photo-credits-list').replaceChildren(...rows);
  $('photo-credits').hidden = !rows.length;
  if (focusId && focusURL) {
    const row = rows.find(function (item) { return item.dataset.creditId === focusId; });
    const link = Array.from(row?.querySelectorAll('a') || []).find(function (item) { return item.href === focusURL; });
    link?.focus({ preventScroll: true });
  }
}

async function useExample(person) {
  if (state.submitting || probeSource.loading || !state.connected || person.esempio !== true) return;
  const url = galleryPhotoURL(person.foto_url);
  if (!url) {
    showError('probe-source-error', 'La foto d’esempio non è disponibile.');
    return;
  }
  const loaded = await probeSource.loadGalleryPhoto(url, person.nome);
  if (!loaded) return;
  $('probe-title').focus({ preventScroll: true });
  $('probe-source').scrollIntoView({ block: 'nearest' });
}

function gallerySearchText(value) {
  return String(value || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLocaleLowerCase('it-IT');
}

function filteredPeople(people) {
  const terms = gallerySearchText(state.galleryQuery).trim().split(/\s+/).filter(Boolean);
  if (!terms.length) return people;
  return people.filter(function (person) {
    const text = gallerySearchText(`${person.nome || ''} ${person.nota || ''}`);
    return terms.every(function (term) { return text.includes(term); });
  });
}

function searchGallery() {
  state.galleryQuery = $('gallery-search').value;
  state.galleryVisible = GALLERY_PAGE_SIZE;
  renderGallery(state.people);
}

function showMorePeople() {
  const firstNew = $('gallery').children.length;
  state.galleryVisible += GALLERY_PAGE_SIZE;
  renderGallery(state.people);
  const actions = Array.from($('gallery').children[firstNew]?.querySelectorAll('button') || []);
  actions.find(function (button) { return !button.disabled; })?.focus({ preventScroll: true });
}

function renderGallery(people) {
  const matches = filteredPeople(people);
  const visible = matches.slice(0, state.galleryVisible);
  const searching = Boolean(state.galleryQuery.trim());
  $('gallery-count').textContent = searching ? `${matches.length} di ${people.length}` : String(people.length);
  $('gallery-tools').hidden = !people.length && !searching;
  $('gallery-empty').hidden = Boolean(matches.length);
  $('gallery-empty').textContent = people.length ? 'Nessuna persona trovata. Prova un altro nome o una nota.' : 'Aggiungi la prima persona per iniziare.';
  $('gallery-navigation').hidden = !matches.length;
  $('gallery-shown').textContent = `Mostrate ${visible.length} di ${matches.length}`;
  $('gallery-more').hidden = visible.length >= matches.length;
  const signature = JSON.stringify([people, state.galleryQuery, state.galleryVisible]);
  if (signature === state.gallerySignature) return;
  state.gallerySignature = signature;
  const focused = document.activeElement;
  const focusedRow = focused?.closest('[data-person-id]');
  const focusId = focusedRow?.dataset.personId;
  const focusAction = focused?.dataset.personAction;
  const rows = visible.map(function (person) {
    const row = node('article', 'person-row');
    row.dataset.personId = String(person.id);
    const url = galleryPhotoURL(person.foto_url);
    let photo;
    if (url) {
      photo = node('img', 'person-photo');
      photo.src = url;
      photo.alt = '';
      photo.loading = 'lazy';
    } else {
      photo = node('div', 'person-photo person-placeholder');
      photo.setAttribute('aria-hidden', 'true');
      photo.append(icon('image'));
    }
    const copy = node('div', 'person-copy');
    const threshold = node('span', 'person-threshold', `Soglia ${person.soglia}`);
    if (person.esempio === true) threshold.append(node('span', 'person-badge', 'Esempio'));
    copy.append(node('strong', 'person-name', person.nome), threshold);
    if (typeof person.nota === 'string' && person.nota) copy.append(node('span', 'person-note', person.nota));
    const actions = node('div', 'person-actions');
    if (person.esempio === true && url) {
      const use = personAction(`Usa ${person.nome} per una prova`, 'arrow', function () { return useExample(person); });
      use.dataset.exampleAction = 'true';
      actions.append(use);
    }
    actions.append(
      personAction(`Modifica ${person.nome}`, 'edit', function () { openPerson(person); }),
      personAction(`Rimuovi ${person.nome}`, 'trash', function () { openDelete(person); }),
    );
    row.append(photo, copy, actions);
    return row;
  });
  $('gallery').replaceChildren(...rows);
  renderCredits(people);
  if (focusId) {
    const row = rows.find(function (item) { return item.dataset.personId === focusId; });
    const button = Array.from(row?.querySelectorAll('button') || []).find(function (item) { return item.dataset.personAction === focusAction; });
    if (button) button.focus({ preventScroll: true });
    else if (!$('gallery-tools').hidden) $('gallery-search').focus({ preventScroll: true });
    else $('add-person').focus({ preventScroll: true });
  }
  updateControls();
}

async function loadGallery() {
  const version = ++state.galleryVersion;
  const session = state.sessionVersion;
  const connection = state.connectionGeneration;
  try {
    const data = await api('/api/galleria', { timeout: 12000 });
    if (version !== state.galleryVersion || session !== state.sessionVersion || connection !== state.connectionGeneration || state.leaving) return;
    applyGallery(data);
  } catch (error) {
    if (version !== state.galleryVersion || session !== state.sessionVersion || connection !== state.connectionGeneration || state.leaving) return;
    $('gallery-empty').hidden = true;
    showError('gallery-error', error);
  }
}

function applyGallery(data) {
  state.galleryVersion += 1;
  state.people = Array.isArray(data.iscritti) ? data.iscritti : [];
  renderGallery(state.people);
  showError('gallery-error', null);
  updateControls();
}

function openPerson(person = null) {
  if (state.personBusy) return;
  probeSource.stopCamera();
  state.editingId = person?.id ?? null;
  $('person-form').reset();
  personSource.reset();
  $('person-name').value = person?.nome ?? '';
  $('person-threshold').value = person?.soglia ?? 273;
  $('person-title').textContent = person ? 'Modifica persona' : 'Aggiungi persona';
  $('save-person').textContent = person ? 'Salva modifiche' : 'Aggiungi persona';
  $('person-source').hidden = Boolean(person);
  showError('person-error', null);
  $('person-progress').hidden = true;
  $('person-dialog').showModal();
  updateControls();
  $('person-name').focus();
}

function closePerson() {
  if (state.personBusy) return;
  $('person-dialog').close();
}

function lockPerson(value) {
  state.personBusy = value;
  $('person-name').disabled = value;
  $('person-threshold').disabled = value;
  $('cancel-person').disabled = value;
  $('close-person').disabled = value;
  $('person-progress').hidden = !value;
  personSource.setLocked(value);
  updateControls();
}

async function savePerson(event) {
  event.preventDefault();
  if (state.personBusy || personSource.loading || !$('person-form').reportValidity()) return;
  const name = $('person-name').value.trim();
  const threshold = Number($('person-threshold').value);
  if (!name || !Number.isSafeInteger(threshold)) {
    showError('person-error', 'Inserisci un nome e una soglia intera valida.');
    return;
  }
  const editing = state.editingId;
  const session = state.sessionVersion;
  lockPerson(true);
  showError('person-error', null);
  try {
    const body = { nome: name, soglia: threshold };
    if (!editing) body.frames = await personSource.getFrames(function (count, total) {
      $('person-progress-label').textContent = `Acquisizione foto ${count} di ${total}…`;
    });
    if (state.leaving || session !== state.sessionVersion) return;
    $('person-progress-label').textContent = 'Preparazione della galleria…';
    const path = editing ? `/api/galleria/${encodeURIComponent(editing)}` : '/api/galleria';
    await api(path, { method: editing ? 'PATCH' : 'POST', body });
    if (state.leaving || session !== state.sessionVersion) return;
    lockPerson(false);
    $('person-dialog').close();
    toast(editing ? 'Modifiche salvate.' : 'Persona aggiunta.');
    await loadGallery();
  } catch (error) {
    if (!state.leaving && session === state.sessionVersion) showError('person-error', error);
  } finally {
    if (session === state.sessionVersion) lockPerson(false);
  }
}

function openDelete(person) {
  if (state.deleteBusy) return;
  state.deletingId = person.id;
  $('delete-name').textContent = person.nome;
  showError('delete-error', null);
  $('delete-dialog').showModal();
  $('cancel-delete').focus();
}

function closeDelete() {
  if (!state.deleteBusy) $('delete-dialog').close();
}

async function deletePerson() {
  if (state.deleteBusy || !state.deletingId) return;
  state.deleteBusy = true;
  const session = state.sessionVersion;
  for (const id of ['confirm-delete', 'close-delete', 'cancel-delete']) $(id).disabled = true;
  $('confirm-delete').textContent = 'Rimozione…';
  showError('delete-error', null);
  try {
    await api(`/api/galleria/${encodeURIComponent(state.deletingId)}`, { method: 'DELETE' });
    if (state.leaving || session !== state.sessionVersion) return;
    $('delete-dialog').close();
    toast('Persona rimossa.');
    await loadGallery();
  } catch (error) {
    if (!state.leaving && session === state.sessionVersion) showError('delete-error', error);
  } finally {
    if (session === state.sessionVersion) unlockDelete();
  }
}

function unlockDelete() {
  state.deleteBusy = false;
  for (const id of ['confirm-delete', 'close-delete', 'cancel-delete']) $(id).disabled = false;
  $('confirm-delete').textContent = 'Rimuovi';
}

function resultsOf(request) {
  if (Array.isArray(request.risultati) && request.risultati.length) return request.risultati;
  if (request.esito && request.motore !== 'confronto') return [{ motore: request.motore, esito: request.esito, selected_id: request.selected_id, selected_name: request.selected_name, tempi_ms: request.tempi_ms }];
  return [];
}

function resultText(result) {
  if (result.esito === 'aperto') {
    if (result.selected_name) return `Accesso consentito · ${result.selected_name}`;
    if (Number.isInteger(result.selected_id) && result.selected_id > 0) return `Accesso consentito · ID ${result.selected_id}`;
    return 'Accesso consentito';
  }
  if (result.esito === 'negato') return 'Accesso negato';
  return 'Esito non disponibile';
}

function resultClass(result) {
  if (result.esito === 'aperto') return 'result-allowed';
  if (result.esito === 'negato') return 'result-denied';
  return '';
}

function measured(value) { return typeof value === 'number' && Number.isFinite(value) && value >= 0; }

function timingText(value) {
  if (!measured(value)) return '—';
  if (value > 0 && value < .001) return '<0,001 ms';
  if (value < 1000) return `${value.toLocaleString('it-IT', { maximumFractionDigits: 3 })} ms`;
  return duration(value);
}

function serverElapsed(request) {
  if (measured(request.timeline?.elapsed_ms)) return request.timeline.elapsed_ms;
  return request.tempo_complessivo_ms;
}

function requestTimes(request) {
  const parts = [];
  if (measured(request.attesa_ms)) parts.push(`Attesa ${duration(request.attesa_ms)}`);
  const results = resultsOf(request);
  if (results.length === 1 && measured(results[0].tempi_ms?.server)) parts.push(`Servizio FHE ${duration(results[0].tempi_ms.server)}`);
  if (measured(serverElapsed(request))) parts.push(`Complessivo ${timingText(serverElapsed(request))}`);
  return parts.join(' · ');
}

const SPAN_LABELS = {
  job: 'Elaborazione', queue: 'Coda', prepare: 'Preparazione foto', engine: 'Motore',
  encryption: 'Cifratura', fhe: 'Calcolo FHE', decryption: 'Decifratura', setup: 'Preparazione motore',
};

function timelineData(request) {
  const timeline = request.timeline;
  if (!timeline || !measured(timeline.elapsed_ms) || !Array.isArray(timeline.spans)) return null;
  const spans = new Map();
  for (const span of timeline.spans) {
    if (!span || typeof span.id !== 'string' || spans.has(span.id) || !Object.hasOwn(SPAN_LABELS, span.kind)) continue;
    if (span.parent_id !== null && typeof span.parent_id !== 'string') continue;
    if (!measured(span.start_ms) || (span.end_ms !== null && !measured(span.end_ms))) continue;
    const end = span.end_ms === null ? timeline.elapsed_ms : span.end_ms;
    if (end < span.start_ms) continue;
    spans.set(span.id, { ...span, end, active: span.end_ms === null });
  }
  const root = spans.get('job');
  if (!root || root.kind !== 'job' || root.parent_id !== null) return null;
  const children = new Map();
  for (const span of spans.values()) {
    if (!children.has(span.parent_id)) children.set(span.parent_id, []);
    children.get(span.parent_id).push(span);
  }
  for (const siblings of children.values()) siblings.sort(function (left, right) { return left.start_ms - right.start_ms; });
  const connected = [];
  const visited = new Set();
  function visit(span) {
    if (visited.has(span.id)) return;
    visited.add(span.id);
    connected.push(span);
    for (const child of children.get(span.id) || []) visit(child);
  }
  visit(root);
  const extent = Math.max(timeline.elapsed_ms, ...connected.map(function (span) { return span.end; }));
  return { root, children, scale: extent || 1 };
}

function svgNode(tag, attributes) {
  const element = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
  return element;
}

function timelineAxis(scale) {
  const axis = node('div', 'waterfall-row timeline-axis');
  const ticks = node('div', 'timeline-ticks');
  for (const part of [0, .25, .5, .75, 1]) ticks.append(node('span', 'timeline-tick', timingText(scale * part)));
  axis.append(node('span', 'waterfall-label', 'Dall’accodamento'), ticks, node('span', 'waterfall-value', 'Durata'));
  return axis;
}

function spanEngine(span, inherited = null) {
  if (span.engine === 'attuale' || span.engine === 'a28') return span.engine;
  if (span.kind === 'engine' && (span.id === 'attuale' || span.id === 'a28')) return span.id;
  return inherited;
}

function timelineRow(span, scale, engine) {
  let label = SPAN_LABELS[span.kind];
  if (span.kind === 'engine') label = engineName(engine);
  else if (span.kind === 'fhe' && engine === 'attuale') label = 'Servizio FHE';
  const classes = ['waterfall-row', `timeline-${span.kind}`];
  if (engine) classes.push(`timeline-${engine}`);
  if (span.kind === 'engine') classes.push('waterfall-engine');
  if (span.active) classes.push('timeline-active');
  if (span.status === 'error') classes.push('timeline-error');
  const row = node('div', classes.join(' '));
  row.dataset.spanId = span.id;
  const track = node('div', 'waterfall-track');
  const svg = svgNode('svg', { viewBox: `0 0 ${scale} 16`, preserveAspectRatio: 'none', class: 'timeline-svg', 'aria-hidden': 'true' });
  for (const part of [0, .25, .5, .75, 1]) {
    svg.append(svgNode('line', { x1: scale * part, x2: scale * part, y1: 0, y2: 16, class: 'timeline-grid' }));
  }
  const durationMs = span.end - span.start_ms;
  svg.append(svgNode('rect', { x: span.start_ms, y: 4, width: durationMs, height: 8, class: 'timeline-bar' }));
  if (durationMs === 0) svg.append(svgNode('line', { x1: span.start_ms, x2: span.start_ms, y1: 3, y2: 13, class: 'timeline-zero' }));
  const offsets = `Da ${timingText(span.start_ms)} a ${timingText(span.end)} dall’accodamento.`;
  track.title = offsets;
  track.append(svg, node('span', 'sr-only', offsets));
  const value = node('span', 'waterfall-value', timingText(durationMs));
  if (span.status === 'error') value.append(node('small', '', 'Interrotta'));
  else if (span.active) value.append(node('small', '', 'In corso'));
  row.append(node('span', 'waterfall-label', label), track, value);
  return row;
}

function renderTimeline(timeline, results) {
  const waterfall = node('div', 'waterfall waterfall-timeline');
  const shownResults = new Set();
  const visited = new Set();
  let includesLocalTransfer = false;
  function branch(span, inherited = null) {
    if (visited.has(span.id)) return null;
    visited.add(span.id);
    const engine = spanEngine(span, inherited);
    if (span.kind === 'fhe' && engine === 'attuale') includesLocalTransfer = true;
    const row = timelineRow(span, timeline.scale, engine);
    const children = timeline.children.get(span.id) || [];
    if (span.kind !== 'engine' && !children.length) return row;
    const group = node('div', span.kind === 'engine' ? 'waterfall-group' : 'timeline-branch');
    group.append(row);
    if (span.kind === 'engine') {
      const result = results.find(function (item) { return item.motore === engine; });
      if (result) {
        shownResults.add(result);
        group.append(node('p', `waterfall-result ${resultClass(result)}`, resultText(result)));
        if (measured(result.tempi_ms?.server)) group.append(node('p', 'waterfall-measure', `Solo calcolo FHE: ${timingText(result.tempi_ms.server)}.`));
      }
    }
    if (children.length) {
      const nested = node('div', 'waterfall-children');
      for (const child of children) {
        const childElement = branch(child, engine);
        if (childElement) nested.append(childElement);
      }
      group.append(nested);
    }
    return group;
  }
  waterfall.append(timelineAxis(timeline.scale), timelineRow(timeline.root, timeline.scale, null));
  visited.add(timeline.root.id);
  for (const child of timeline.children.get(timeline.root.id) || []) {
    const element = branch(child);
    if (element) waterfall.append(element);
  }
  for (const result of results) {
    if (!shownResults.has(result)) waterfall.append(node('p', `waterfall-result ${resultClass(result)}`, `${engineName(result.motore)}: ${resultText(result)}`));
  }
  if (includesLocalTransfer) waterfall.append(node('p', 'waterfall-note', 'In Attuale, Servizio FHE comprende il trasferimento locale oltre al calcolo.'));
  return waterfall;
}

function durationRow(label, value, className = '') {
  const row = node('div', `waterfall-row ${className}`);
  row.append(node('span', 'waterfall-label', label), node('span', 'waterfall-value', timingText(value)));
  return row;
}

function renderDurations(request, results) {
  const waterfall = node('div', 'waterfall waterfall-durations');
  waterfall.append(durationRow('Elaborazione', serverElapsed(request)), durationRow('Coda', request.attesa_ms), durationRow('Preparazione foto', request.preparazione_ms));
  const engines = request.motore === 'confronto' ? ['attuale', 'a28'] : [request.motore];
  for (const engine of engines) {
    const result = results.find(function (item) { return item.motore === engine; });
    const group = node('div', 'waterfall-group');
    group.append(durationRow(engineName(engine), result?.tempi_ms?.totale, 'waterfall-engine'));
    if (result) group.append(node('p', `waterfall-result ${resultClass(result)}`, resultText(result)));
    const children = node('div', 'waterfall-children');
    for (const [key, label] of [['cifratura', 'Cifratura'], ['server', 'Calcolo FHE'], ['decifratura', 'Decifratura']]) {
      children.append(durationRow(label, result?.tempi_ms?.[key]));
    }
    group.append(children);
    waterfall.append(group);
  }
  return waterfall;
}

function requestDetails(request) {
  const content = node('div', 'request-details');
  const results = resultsOf(request);
  if (Number.isInteger(request.iscritti) && request.iscritti >= 0) {
    content.append(node('p', 'request-context', `Galleria · ${request.iscritti} ${request.iscritti === 1 ? 'persona' : 'persone'}`));
  }
  const timeline = timelineData(request);
  content.append(timeline ? renderTimeline(timeline, results) : renderDurations(request, results));
  if (request.errore) content.append(node('p', 'request-error', request.errore));
  const note = timeline ? 'Tempi dall’accodamento sul server. Le sottofasi sono comprese nella durata del motore.' : 'Sono disponibili solo le durate, senza gli istanti delle singole fasi.';
  content.append(node('p', 'waterfall-note', note));
  content.append(node('p', 'waterfall-note', 'Il POST risponde 202 appena la richiesta viene accettata; l’elaborazione continua sul server.'));
  return content;
}

function renderRequests(requests) {
  const signature = JSON.stringify(requests);
  if (signature === state.requestSignature) return;
  state.requestSignature = signature;
  const open = new Set(Array.from($('requests').querySelectorAll('details[open]')).map(function (item) { return item.closest('[data-request-id]').dataset.requestId; }));
  const focusedRequest = document.activeElement?.closest('[data-request-id]');
  const focusedId = focusedRequest?.dataset.requestId;
  const focusedSummary = document.activeElement?.tagName === 'SUMMARY';
  const rows = requests.map(function (request) {
    const row = node('article', 'request-item');
    row.dataset.requestId = String(request.id);
    const details = node('details');
    details.open = open.has(String(request.id));
    const summary = node('summary', 'request-summary');
    summary.title = `Richiesta ${request.id}`;
    const endpoint = node('span', 'request-endpoint');
    endpoint.append(node('span', 'request-method', 'POST'), node('code', '', '/api/accesso'));
    const metadata = node('span', 'request-meta');
    metadata.append(node('span', 'request-engine', engineName(request.motore)));
    const date = new Date(request.ora);
    if (!Number.isNaN(date.getTime())) {
      const time = node('time', '', date.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
      time.dateTime = date.toISOString();
      time.title = date.toLocaleString('it-IT');
      metadata.append(time);
    }
    const status = node('span', `request-state${request.stato === 'errore' ? ' result-error' : ''}`, STATUS[request.stato] || 'In corso');
    const elapsed = node('span', 'request-duration');
    if (measured(serverElapsed(request))) {
      elapsed.append(node('span', '', timingText(serverElapsed(request))), node('small', '', 'sul server'));
    } else elapsed.append(node('span', 'quiet', '—'));
    summary.append(endpoint, metadata, status, elapsed);
    details.append(summary, requestDetails(request));
    row.append(details);
    return row;
  });
  $('requests').replaceChildren(...rows);
  if (focusedId && focusedSummary) {
    const row = rows.find(function (item) { return item.dataset.requestId === focusedId; });
    row?.querySelector('summary')?.focus({ preventScroll: true });
  }
}

function renderLatest() {
  const request = state.requests.find(function (item) { return String(item.id) === String(state.latestId); });
  if (!request || state.submitting) return;
  const signature = JSON.stringify(request);
  if (signature === state.latestSignature) return;
  state.latestSignature = signature;
  const finished = request.stato === 'completata' || request.stato === 'errore';
  $('probe-progress').hidden = finished;
  $('probe-progress-label').textContent = STATUS[request.stato] || 'Verifica in corso…';
  $('probe-result').hidden = !finished;
  $('probe-result').replaceChildren();
  if (request.stato === 'errore') {
    $('probe-result').append(node('p', 'result-error', request.errore || 'La verifica non è riuscita.'));
  }
  if (finished) {
    const results = resultsOf(request);
    for (const result of results) {
      let text = resultText(result);
      if (request.motore !== 'attuale') text = `${engineName(result.motore)}: ${text}`;
      $('probe-result').append(node('p', resultClass(result), text));
    }
    if (!results.length && request.stato === 'completata') $('probe-result').append(node('p', '', 'Verifica completata. Esito non disponibile.'));
    const timings = requestTimes(request);
    if (timings) $('probe-result').append(node('p', 'quiet', timings));
  }
}

function applyRequests(data) {
  state.requests = Array.isArray(data.richieste) ? data.richieste : [];
  renderRequests(state.requests);
  renderLatest();
  $('requests-count').textContent = String(data.totale ?? state.requests.length);
  $('requests-empty').hidden = Boolean(state.requests.length);
  $('requests-empty').textContent = 'Nessuna richiesta. Avvia una prova qui sopra.';
  $('requests-update').textContent = 'Aggiornamento in tempo reale';
  showError('requests-error', null);
}

async function submitProbe() {
  if ($('submit-probe').disabled || state.submitting) return;
  const session = state.sessionVersion;
  state.submitting = true;
  state.latestId = null;
  state.latestSignature = null;
  probeSource.setLocked(true);
  showError('probe-error', null);
  $('probe-result').hidden = true;
  $('probe-progress').hidden = false;
  $('probe-progress-label').textContent = 'Invio della richiesta…';
  try {
    const frames = await probeSource.getFrames(function (count, total) {
      $('probe-progress-label').textContent = `Acquisizione foto ${count} di ${total}…`;
    });
    if (state.leaving || session !== state.sessionVersion) return;
    $('probe-progress-label').textContent = 'Invio della richiesta…';
    const result = await api('/api/accesso', { method: 'POST', body: { frames, motore: 'attuale' } });
    if (state.leaving || session !== state.sessionVersion) return;
    if (!result.richiesta_id) throw new Error('Il servizio non ha restituito il riferimento della richiesta. Controlla l’elenco prima di riprovare.');
    state.latestId = result.richiesta_id;
    $('probe-progress-label').textContent = 'Richiesta ricevuta. In attesa dello stato…';
    renderLatest();
  } catch (error) {
    if (!state.leaving && session === state.sessionVersion) {
      showError('probe-error', error);
      $('probe-progress').hidden = true;
    }
  } finally {
    if (session === state.sessionVersion) {
      state.submitting = false;
      probeSource.setLocked(false);
      renderLatest();
    }
  }
}

function clearSession() {
  state.sessionVersion += 1;
  state.galleryVersion += 1;
  state.statusVersion += 1;
  state.people = [];
  state.galleryQuery = '';
  state.galleryVisible = GALLERY_PAGE_SIZE;
  $('gallery-search').value = '';
  state.requests = [];
  state.latestId = null;
  state.latestSignature = null;
  state.submitting = false;
  probeSource.setLocked(false);
  probeSource.reset();
  lockPerson(false);
  personSource.reset();
  unlockDelete();
  $('person-dialog').close();
  $('delete-dialog').close();
  $('probe-progress').hidden = true;
  $('probe-result').hidden = true;
  $('probe-result').replaceChildren();
  showError('probe-error', null);
  renderGallery([]);
  renderRequests([]);
  $('gallery-count').textContent = '0';
  $('requests-count').textContent = '0';
}

function updateSession(expiry) {
  if (!expiry) return;
  if (state.sessionExpiry && state.sessionExpiry !== expiry) {
    clearSession();
    toast('La sessione precedente è terminata. È iniziata una nuova sessione.');
  }
  state.sessionExpiry = expiry;
  const date = new Date(expiry);
  $('session-note').textContent = Number.isNaN(date.getTime()) ? 'Sessione temporanea.' : `Sessione temporanea · scade alle ${date.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' })}.`;
}

async function loadStatus() {
  const connection = state.connectionGeneration;
  const version = ++state.statusVersion;
  const session = state.sessionVersion;
  try {
    const data = await api('/api/stato', { timeout: 10000 });
    if (state.leaving || connection !== state.connectionGeneration || version !== state.statusVersion || session !== state.sessionVersion) return false;
    applyStatus(data);
    return true;
  } catch {
    if (state.leaving || connection !== state.connectionGeneration || version !== state.statusVersion || session !== state.sessionVersion) return false;
    state.connected = false;
    updateControls();
    return false;
  }
}

function applyStatus(data) {
  state.statusVersion += 1;
  state.connected = true;
  state.ready = data.pronto === true;
  state.preparationError = data.errore || null;
  state.engines = Array.isArray(data.motori) ? data.motori : [];
  updateSession(data.sessione?.scadenza);
  updateControls();
}

function closeEvents() {
  state.connectionGeneration += 1;
  clearTimeout(state.reconnectTimer);
  state.reconnectTimer = null;
  state.stream?.close();
  state.stream = null;
}

function reconnectEvents() {
  closeEvents();
  state.connected = false;
  updateControls();
  if (state.leaving) return;
  $('requests-update').textContent = 'Riconnessione al servizio…';
  const delay = state.reconnectDelay;
  state.reconnectDelay = Math.min(delay * 2, MAX_RECONNECT_DELAY);
  state.reconnectTimer = setTimeout(function () {
    state.reconnectTimer = null;
    connectEvents();
  }, delay);
}

async function connectEvents() {
  if (state.leaving) return;
  closeEvents();
  const generation = state.connectionGeneration;
  const connected = await loadStatus();
  if (state.leaving || generation !== state.connectionGeneration) return;
  if (!connected) {
    reconnectEvents();
    return;
  }
  try {
    const stream = new EventSource('/api/eventi');
    state.stream = stream;
    let session = state.sessionVersion;
    const received = new Set();
    function active() {
      return !state.leaving && generation === state.connectionGeneration && session === state.sessionVersion && state.stream === stream;
    }
    function receive(kind, apply) {
      stream.addEventListener(kind, function (event) {
        if (!active()) return;
        try {
          const data = JSON.parse(event.data);
          if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Evento non valido.');
          apply(data);
          session = state.sessionVersion;
          received.add(kind);
          if (received.size === 3) state.reconnectDelay = RECONNECT_DELAY;
        } catch {
          reconnectEvents();
        }
      });
    }
    receive('stato', applyStatus);
    receive('galleria', applyGallery);
    receive('richieste', applyRequests);
    stream.addEventListener('scaduta', function () {
      if (!active()) return;
      clearSession();
      state.sessionExpiry = null;
      $('session-note').textContent = 'Sessione terminata. Riconnessione…';
      reconnectEvents();
    });
    stream.addEventListener('error', function () { if (active()) reconnectEvents(); });
  } catch {
    reconnectEvents();
  }
}

$('brand').addEventListener('click', function () { toast('0 oppure ID.'); });
$('add-person').addEventListener('click', function () { openPerson(); });
$('gallery-search').addEventListener('input', searchGallery);
$('gallery-more').addEventListener('click', showMorePeople);
$('close-person').addEventListener('click', closePerson);
$('cancel-person').addEventListener('click', closePerson);
$('person-form').addEventListener('submit', savePerson);
$('person-dialog').addEventListener('cancel', function (event) { if (state.personBusy) event.preventDefault(); });
$('person-dialog').addEventListener('close', function () { personSource.reset(); });
$('close-delete').addEventListener('click', closeDelete);
$('cancel-delete').addEventListener('click', closeDelete);
$('confirm-delete').addEventListener('click', deletePerson);
$('delete-dialog').addEventListener('cancel', function (event) { if (state.deleteBusy) event.preventDefault(); });
$('submit-probe').addEventListener('click', submitProbe);
window.addEventListener('pagehide', function () {
  state.leaving = true;
  state.connected = false;
  closeEvents();
  clearTimeout(state.toastTimer);
  probeSource.stopCamera();
  personSource.stopCamera();
});
window.addEventListener('pageshow', function (event) {
  if (event.persisted) {
    state.leaving = false;
    state.reconnectDelay = RECONNECT_DELAY;
    connectEvents();
  }
});

mountIcons();
updateControls();
connectEvents();
