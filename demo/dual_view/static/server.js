import { Camera, api, duration, galleryPhotoURL, icon, mountIcons, readPhotos, renderPreviews, setConnection } from './shared.js';

mountIcons();
const byId = function (id) { return document.getElementById(id); };
const camera = new Camera(byId('enrollment-camera'));
const personDialog = byId('person-dialog');
const deleteDialog = byId('delete-dialog');
let people = [];
let gallerySignature = '';
let requestSignature = '';
let galleryLoaded = false;
let galleryLoading = null;
let galleryGeneration = 0;
let galleryLastLoaded = 0;
let editingPerson = null;
let deletingPerson = null;
let uploadedFrames = [];
let photoSource = 'upload';
let formBusy = false;
let photoBusy = false;
let deleteBusy = false;
let photoGeneration = 0;
let toastTimer;
let pollTimer;
let pollGeneration = 0;
let leaving = false;

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function showToast(message, kind = 'success') {
  const toast = byId('toast');
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.dataset.kind = kind;
  toast.hidden = false;
  toastTimer = setTimeout(function () { toast.hidden = true; }, 5000);
}

function cardAction(label, iconName, className, action) {
  const button = element('button', `icon-button ${className}`);
  button.type = 'button';
  button.setAttribute('aria-label', label);
  button.title = label;
  button.append(icon(iconName));
  button.addEventListener('click', action);
  return button;
}

function createPersonCard(person) {
  const card = element('article', 'person-card');
  const photo = element('div', 'person-photo');
  const placeholder = element('span', 'person-initial', (person.nome || '?').trim().slice(0, 1).toLocaleUpperCase('it-IT'));
  placeholder.setAttribute('aria-hidden', 'true');
  const photoURL = galleryPhotoURL(person.foto_url);
  if (photoURL) {
    const image = element('img');
    image.src = photoURL;
    image.alt = `Foto di ${person.nome}`;
    image.loading = 'lazy';
    image.decoding = 'async';
    image.addEventListener('error', function () { photo.replaceChildren(placeholder); }, { once: true });
    photo.append(image);
  } else {
    photo.append(placeholder);
  }
  const content = element('div', 'person-content');
  const name = element('h3', 'person-name', person.nome);
  name.title = person.nome;
  const actions = element('div', 'person-actions');
  const buttons = element('div', 'card-buttons');
  buttons.append(
    cardAction(`Modifica ${person.nome}`, 'edit', '', function () { openPerson(person); }),
    cardAction(`Rimuovi ${person.nome}`, 'trash', 'delete', function () { openDelete(person); }),
  );
  actions.append(buttons);
  content.append(name, element('p', 'person-meta', `Soglia ${person.soglia}`), actions);
  card.append(photo, content);
  return card;
}

function renderGallery() {
  const query = byId('search').value.trim().toLocaleLowerCase('it-IT');
  const visible = people.filter(function (person) { return person.nome.toLocaleLowerCase('it-IT').includes(query); });
  const fragment = document.createDocumentFragment();
  visible.forEach(function (person) { fragment.append(createPersonCard(person)); });
  byId('gallery').replaceChildren(fragment);
  byId('gallery').setAttribute('aria-busy', 'false');
  byId('gallery-count').textContent = `${people.length} persone`;
  const resultLabel = visible.length === 1 ? 'risultato' : 'risultati';
  byId('search-count').textContent = query ? `${visible.length} ${resultLabel}` : '';
  byId('search-count').style.fontSize = '11px';
  byId('gallery-empty').hidden = visible.length > 0;
  byId('retry-gallery').hidden = true;
  if (!visible.length) {
    byId('gallery-empty-title').textContent = query ? 'Nessun risultato' : 'Nessun iscritto';
    byId('gallery-empty-message').textContent = query ? 'Modifica o cancella la ricerca.' : 'Aggiungi una persona con una foto o con la fotocamera.';
  }
}

async function loadGallery(force = false) {
  if (force === true) galleryGeneration += 1;
  if (galleryLoading) return galleryLoading;
  galleryLoading = (async function () {
    try {
      let generation;
      do {
        generation = galleryGeneration;
        try {
          const result = await api('/api/galleria', { timeout: 10000 });
          if (generation !== galleryGeneration) continue;
          if (!Array.isArray(result.iscritti)) throw new Error('La galleria non è disponibile.');
          const signature = JSON.stringify(result.iscritti);
          if (signature !== gallerySignature || !galleryLoaded) {
            people = result.iscritti;
            gallerySignature = signature;
            renderGallery();
          }
          galleryLoaded = true;
          galleryLastLoaded = Date.now();
        } catch (error) {
          if (generation !== galleryGeneration) continue;
          if (!galleryLoaded) {
            byId('gallery').setAttribute('aria-busy', 'false');
            byId('gallery-count').textContent = 'Non disponibile';
            byId('gallery-empty-title').textContent = 'Galleria non disponibile';
            byId('gallery-empty-message').textContent = error.message;
            byId('retry-gallery').hidden = false;
          }
        }
      } while (generation !== galleryGeneration);
    } finally {
      galleryLoading = null;
    }
  })();
  return galleryLoading;
}

function byteSize(value) {
  if (!Number.isFinite(value)) return 'n/d';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toLocaleString('it-IT', { maximumFractionDigits: 1 })} KiB`;
  return `${(value / (1024 * 1024)).toLocaleString('it-IT', { maximumFractionDigits: 1 })} MiB`;
}

function createRequest(request) {
  const labels = {
    ricevuta: 'Richiesta ricevuta',
    in_elaborazione: 'Elaborazione in corso',
    completata: 'Risposta cifrata pronta',
    errore: 'Elaborazione interrotta',
  };
  const row = element('article', 'request');
  row.dataset.state = request.stato;
  const top = element('div', 'request-top');
  const title = element('strong', '', labels[request.stato] || 'Richiesta ricevuta');
  const date = new Date(request.ora);
  const time = element('time', 'request-time', Number.isNaN(date.getTime()) ? 'n/d' : date.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
  if (!Number.isNaN(date.getTime())) {
    time.dateTime = date.toISOString();
    time.title = date.toLocaleString('it-IT');
  }
  top.append(title, time);
  const identifier = element('p', 'request-status', `Richiesta ${String(request.id).slice(0, 8)}`);
  identifier.title = String(request.id);
  const bottom = element('div', 'request-bottom');
  bottom.append(element('span', '', `${byteSize(request.byte_richiesta)} ricevuti`), element('span', 'request-duration', duration(request.durata_ms)));
  row.append(top, identifier, bottom);
  if (request.stato === 'errore' && request.errore) row.append(element('p', 'request-status request-error', request.errore));
  const details = element('details');
  details.append(element('summary', '', 'Dettagli'));
  if (request.impronta) details.append(element('p', '', `Impronta: ${request.impronta}`));
  details.append(element('p', '', `Risposta cifrata: ${byteSize(request.byte_risposta)}`));
  row.append(details);
  return row;
}

function renderRequests(result) {
  const requests = Array.isArray(result.richieste) ? result.richieste.slice(0, 30) : [];
  const signature = JSON.stringify(requests);
  if (signature !== requestSignature) {
    const expanded = new Set();
    const focusedRequest = document.activeElement?.closest('.request')?.dataset.id;
    for (const row of byId('requests').children) {
      if (row.querySelector('details')?.open) expanded.add(row.dataset.id);
    }
    const fragment = document.createDocumentFragment();
    requests.forEach(function (request) {
      const row = createRequest(request);
      row.dataset.id = request.id;
      row.querySelector('details').open = expanded.has(String(request.id));
      fragment.append(row);
    });
    byId('requests').replaceChildren(fragment);
    if (focusedRequest) {
      for (const row of byId('requests').children) {
        if (row.dataset.id === focusedRequest) row.querySelector('summary').focus({ preventScroll: true });
      }
    }
    requestSignature = signature;
  }
  byId('requests-empty').hidden = requests.length > 0;
  byId('requests-empty-title').textContent = 'Nessuna richiesta';
  byId('requests-empty-message').textContent = 'Avvia un tentativo dal client.';
  byId('feed-footer').textContent = result.totale > 30 ? 'Ultime 30 richieste · aggiornamento automatico' : 'Aggiornamento automatico';
}

async function refreshDashboard(generation = pollGeneration) {
  if (leaving || generation !== pollGeneration) return;
  const results = await Promise.allSettled([
    api('/api/stato', { timeout: 8000 }),
    api('/api/richieste', { timeout: 8000 }),
  ]);
  if (leaving || generation !== pollGeneration) return;
  const statusResult = results[0];
  if (statusResult.status === 'fulfilled') {
    const status = statusResult.value;
    setConnection(byId('connection'), Boolean(status.pronto));
    byId('stat-people').textContent = status.iscritti.toLocaleString('it-IT');
    byId('stat-requests').textContent = status.richieste.toLocaleString('it-IT');
    byId('stat-duration').textContent = duration(status.ultima_durata_ms);
    byId('activity-subtitle').textContent = status.in_corso ? `${status.in_corso} in elaborazione` : '';
    byId('service-notice').hidden = Boolean(status.pronto);
    byId('service-notice').textContent = status.errore || 'Avvio del servizio in corso.';
    if (!galleryLoaded || people.length !== status.iscritti || Date.now() - galleryLastLoaded > 15000) loadGallery();
  } else {
    setConnection(byId('connection'), false);
    byId('service-notice').textContent = 'Servizio non raggiungibile. I dati mostrati potrebbero non essere aggiornati.';
    byId('service-notice').hidden = false;
  }
  const requestsResult = results[1];
  if (requestsResult.status === 'fulfilled') {
    renderRequests(requestsResult.value);
    byId('feed-live').textContent = 'In diretta';
    byId('feed-live').dataset.state = 'live';
  } else {
    byId('feed-live').textContent = 'In pausa';
    byId('feed-live').dataset.state = 'paused';
    byId('feed-footer').textContent = 'Riconnessione automatica in corso';
    if (!byId('requests').children.length) {
      byId('requests-empty-title').textContent = 'Richieste non disponibili';
      byId('requests-empty-message').textContent = 'Riconnessione in corso.';
    }
  }
  pollTimer = setTimeout(function () { refreshDashboard(generation); }, 1800);
}

function resetCameraPreview() {
  byId('enrollment-camera').hidden = true;
  byId('enrollment-camera-empty').hidden = false;
  byId('enrollment-camera-overlay').hidden = true;
}

function switchSource(source) {
  if (formBusy || photoBusy) return;
  photoSource = source;
  photoGeneration += 1;
  camera.stop();
  resetCameraPreview();
  byId('upload-tab').setAttribute('aria-pressed', String(source === 'upload'));
  byId('camera-tab').setAttribute('aria-pressed', String(source === 'camera'));
  byId('upload-zone').hidden = source !== 'upload';
  byId('enrollment-camera-box').hidden = source !== 'camera';
  byId('person-error').hidden = true;
  updateFormControls();
}

function updateFormControls() {
  const busy = formBusy || photoBusy;
  const sourceReady = editingPerson || (photoSource === 'camera' ? camera.active : uploadedFrames.length > 0);
  byId('save-person').disabled = busy || !sourceReady;
  for (const id of ['person-name', 'person-threshold', 'upload-tab', 'camera-tab', 'choose-enrollment-photos', 'start-enrollment-camera']) byId(id).disabled = busy;
  byId('close-person').disabled = formBusy;
  byId('cancel-person').disabled = formBusy;
  byId('person-form').setAttribute('aria-busy', String(busy));
}

function openPerson(person = null) {
  editingPerson = person;
  uploadedFrames = [];
  photoBusy = false;
  formBusy = false;
  photoGeneration += 1;
  byId('person-form').reset();
  byId('person-name').value = person?.nome || '';
  byId('person-threshold').value = person ? person.soglia : 273;
  byId('person-threshold').min = String(Number.MIN_SAFE_INTEGER);
  byId('person-threshold').max = String(Number.MAX_SAFE_INTEGER);
  byId('person-dialog-title').textContent = person ? 'Modifica persona' : 'Aggiungi persona';
  byId('person-dialog-description').textContent = person ? 'Nome e soglia.' : 'Nome, soglia e foto.';
  byId('save-person').textContent = person ? 'Salva modifiche' : 'Aggiungi persona';
  byId('enrollment-source').hidden = Boolean(person);
  byId('person-error').hidden = true;
  byId('person-progress').hidden = true;
  byId('enrollment-preview').replaceChildren();
  byId('enrollment-preview').hidden = true;
  byId('upload-description').textContent = 'Da 1 a 3 foto del volto';
  byId('choose-enrollment-photos').textContent = 'Scegli foto';
  const photoURL = galleryPhotoURL(person?.foto_url);
  byId('edit-photo').hidden = !photoURL;
  byId('edit-photo-image').removeAttribute('src');
  if (photoURL) {
    byId('edit-photo-image').src = photoURL;
    byId('edit-photo-image').alt = `Foto di ${person.nome}`;
  }
  switchSource('upload');
  personDialog.showModal();
  byId('person-name').focus();
}

function closePerson() {
  if (!formBusy) personDialog.close();
}

async function startEnrollmentCamera() {
  photoBusy = true;
  byId('person-error').hidden = true;
  byId('start-enrollment-camera').textContent = 'Apertura…';
  updateFormControls();
  const generation = photoGeneration;
  try {
    const started = await camera.start();
    if (!started || generation !== photoGeneration || !personDialog.open) return;
    byId('enrollment-camera').hidden = false;
    byId('enrollment-camera-empty').hidden = true;
    byId('enrollment-camera-overlay').hidden = false;
  } catch (error) {
    if (generation === photoGeneration && personDialog.open) showPersonError(error.message);
  } finally {
    if (generation === photoGeneration) photoBusy = false;
    byId('start-enrollment-camera').textContent = 'Attiva fotocamera';
    updateFormControls();
  }
}

function showPersonError(message) {
  byId('person-error').textContent = message;
  byId('person-error').hidden = false;
}

async function prepareEnrollmentPhotos(files) {
  if (!files.length || formBusy || photoBusy) return;
  photoBusy = true;
  byId('person-error').hidden = true;
  const generation = photoGeneration;
  updateFormControls();
  try {
    const frames = await readPhotos(files);
    if (generation !== photoGeneration || !personDialog.open) return;
    uploadedFrames = frames;
    renderPreviews(byId('enrollment-preview'), frames);
    byId('enrollment-preview').hidden = false;
    byId('upload-description').textContent = frames.length === 1 ? '1 foto selezionata' : `${frames.length} foto selezionate`;
    byId('choose-enrollment-photos').textContent = 'Cambia foto';
  } catch (error) {
    if (generation === photoGeneration && personDialog.open) showPersonError(error.message);
  } finally {
    if (generation === photoGeneration) photoBusy = false;
    byId('enrollment-photos').value = '';
    updateFormControls();
  }
}

async function savePerson(event) {
  event.preventDefault();
  if (formBusy || photoBusy || !byId('person-form').reportValidity()) return;
  const name = byId('person-name').value.trim();
  const threshold = Number(byId('person-threshold').value);
  if (!name) { showPersonError('Inserisci un nome per la persona.'); return; }
  if (!Number.isSafeInteger(threshold)) { showPersonError('Inserisci una soglia intera valida.'); return; }
  formBusy = true;
  byId('person-error').hidden = true;
  byId('person-progress').hidden = false;
  byId('person-progress-label').textContent = editingPerson ? 'Salvataggio…' : 'Iscrizione in corso…';
  updateFormControls();
  try {
    if (editingPerson) {
      await api(`/api/iscritti/${encodeURIComponent(editingPerson.id)}`, { method: 'PATCH', body: { nome: name, soglia: threshold } });
    } else {
      let frames = uploadedFrames;
      if (photoSource === 'camera') {
        frames = await camera.capture(function (current, total) { byId('person-progress-label').textContent = `Acquisizione ${current} di ${total}…`; });
      }
      if (!frames.length) throw new Error('Scegli almeno una foto o attiva la fotocamera.');
      byId('person-progress-label').textContent = 'Iscrizione in corso…';
      await api('/api/iscritti', { method: 'POST', body: { nome: name, frames, soglia: threshold } });
    }
    showToast(editingPerson ? 'Modifiche salvate.' : `${name}: iscrizione completata.`);
    formBusy = false;
    personDialog.close();
    galleryLastLoaded = 0;
    await loadGallery(true);
  } catch (error) {
    showPersonError(error.message);
  } finally {
    formBusy = false;
    byId('person-progress').hidden = true;
    updateFormControls();
  }
}

function openDelete(person) {
  deletingPerson = person;
  byId('delete-name').textContent = person.nome;
  byId('delete-error').hidden = true;
  deleteDialog.showModal();
  byId('cancel-delete').focus();
}

function closeDelete() {
  if (!deleteBusy) deleteDialog.close();
}

async function deletePerson() {
  if (!deletingPerson || deleteBusy) return;
  deleteBusy = true;
  byId('delete-error').hidden = true;
  for (const id of ['close-delete', 'cancel-delete', 'confirm-delete']) byId(id).disabled = true;
  byId('confirm-delete').textContent = 'Rimozione…';
  try {
    await api(`/api/iscritti/${encodeURIComponent(deletingPerson.id)}`, { method: 'DELETE' });
    showToast('Iscrizione rimossa.');
    deleteDialog.close();
    galleryLastLoaded = 0;
    await loadGallery(true);
  } catch (error) {
    byId('delete-error').textContent = error.message;
    byId('delete-error').hidden = false;
  } finally {
    deleteBusy = false;
    byId('confirm-delete').textContent = 'Sì, rimuovi';
    for (const id of ['close-delete', 'cancel-delete', 'confirm-delete']) byId(id).disabled = false;
  }
}

byId('add-person').addEventListener('click', function () { openPerson(); });
byId('search').addEventListener('input', function () { if (galleryLoaded) renderGallery(); });
byId('retry-gallery').addEventListener('click', loadGallery);
byId('close-person').addEventListener('click', closePerson);
byId('cancel-person').addEventListener('click', closePerson);
byId('upload-tab').addEventListener('click', function () { switchSource('upload'); });
byId('camera-tab').addEventListener('click', function () { switchSource('camera'); });
byId('start-enrollment-camera').addEventListener('click', startEnrollmentCamera);
byId('choose-enrollment-photos').addEventListener('click', function () { byId('enrollment-photos').click(); });
byId('enrollment-photos').addEventListener('change', function (event) { prepareEnrollmentPhotos(event.target.files); });
byId('person-form').addEventListener('submit', savePerson);
personDialog.addEventListener('cancel', function (event) { if (formBusy) event.preventDefault(); });
personDialog.addEventListener('close', function () {
  photoGeneration += 1;
  camera.stop();
  uploadedFrames = [];
  photoBusy = false;
  byId('enrollment-preview').replaceChildren();
});
for (const eventName of ['dragenter', 'dragover']) {
  byId('upload-zone').addEventListener(eventName, function (event) {
    event.preventDefault();
    if (!formBusy && !photoBusy) byId('upload-zone').dataset.drag = 'true';
  });
}
byId('upload-zone').addEventListener('dragleave', function () { byId('upload-zone').dataset.drag = 'false'; });
byId('upload-zone').addEventListener('drop', function (event) {
  event.preventDefault();
  byId('upload-zone').dataset.drag = 'false';
  prepareEnrollmentPhotos(event.dataTransfer.files);
});
byId('close-delete').addEventListener('click', closeDelete);
byId('cancel-delete').addEventListener('click', closeDelete);
byId('confirm-delete').addEventListener('click', deletePerson);
deleteDialog.addEventListener('cancel', function (event) { if (deleteBusy) event.preventDefault(); });
window.addEventListener('pagehide', function () {
  leaving = true;
  pollGeneration += 1;
  clearTimeout(pollTimer);
  camera.stop();
});
window.addEventListener('pageshow', function (event) {
  if (event.persisted) {
    leaving = false;
    resetCameraPreview();
    updateFormControls();
    refreshDashboard();
  }
});
loadGallery();
refreshDashboard();
