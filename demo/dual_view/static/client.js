import { Camera, api, duration, mountIcons, readPhotos, renderPreviews, setConnection } from './shared.js';

mountIcons();
const byId = function (id) { return document.getElementById(id); };
const camera = new Camera(byId('camera'));
let uploadedFrames = [];
let source = null;
let busy = false;
let serviceReady = false;
let pollTimer;
let pollGeneration = 0;
let leaving = false;

function updateControls() {
  byId('access').disabled = busy || !serviceReady || !(camera.active || uploadedFrames.length);
  byId('start-camera').disabled = busy;
  byId('choose-photos').disabled = busy;
  byId('reset-source').disabled = busy;
}

function showResult(kind, title, message, milliseconds) {
  const result = byId('result');
  result.dataset.kind = kind;
  byId('result-symbol').textContent = kind === 'aperto' ? '✓' : '!';
  byId('result-title').textContent = title;
  byId('result-message').textContent = message;
  byId('result-time').hidden = !Number.isFinite(milliseconds);
  byId('result-time').textContent = `Durata: ${duration(milliseconds)}`;
  result.hidden = false;
}

function setBusy(value, label = 'Verifica in corso…') {
  busy = value;
  byId('access').setAttribute('aria-busy', String(value));
  byId('access-label').textContent = value ? label : 'Verifica accesso';
  byId('access-icon').replaceChildren();
  byId('access-icon').hidden = !value;
  if (value) {
    const spinner = document.createElement('span');
    spinner.className = 'spinner';
    byId('access-icon').append(spinner);
  }
  updateControls();
}

function resetSource() {
  camera.stop();
  source = null;
  uploadedFrames = [];
  byId('camera').hidden = true;
  byId('camera-empty').hidden = false;
  byId('camera-overlay').hidden = true;
  byId('upload-preview').hidden = true;
  byId('upload-preview').replaceChildren();
  byId('reset-source').hidden = true;
  byId('source-caption').textContent = '3 scatti con fotocamera';
  byId('result').hidden = true;
  updateControls();
}

async function startCamera() {
  resetSource();
  setBusy(true, 'Apertura della fotocamera…');
  try {
    if (!await camera.start()) return;
    source = 'camera';
    byId('camera').hidden = false;
    byId('camera-empty').hidden = true;
    byId('camera-overlay').hidden = false;
    byId('reset-source').textContent = 'Disattiva';
    byId('reset-source').hidden = false;
  } catch (error) {
    showResult('error', 'Fotocamera non disponibile', error.message);
  } finally {
    setBusy(false);
  }
}

async function choosePhotos(event) {
  if (!event.target.files.length) return;
  setBusy(true, 'Preparazione delle foto…');
  byId('result').hidden = true;
  try {
    const frames = await readPhotos(event.target.files);
    resetSource();
    uploadedFrames = frames;
    source = 'upload';
    renderPreviews(byId('upload-preview'), frames);
    byId('upload-preview').hidden = false;
    byId('camera-empty').hidden = true;
    byId('source-caption').textContent = frames.length === 1 ? '1 foto selezionata' : `${frames.length} foto selezionate`;
    byId('reset-source').textContent = 'Rimuovi';
    byId('reset-source').hidden = false;
  } catch (error) {
    showResult('error', 'Controlla le foto', error.message);
  } finally {
    event.target.value = '';
    setBusy(false);
  }
}

async function attemptAccess() {
  if (busy || !serviceReady) return;
  byId('result').hidden = true;
  setBusy(true);
  try {
    let frames = uploadedFrames;
    if (source === 'camera') {
      frames = await camera.capture(function (current, total) {
        byId('access-label').textContent = `Acquisizione ${current} di ${total}…`;
      });
    }
    if (!frames.length) throw new Error('Attiva la fotocamera oppure scegli una foto.');
    byId('access-label').textContent = 'Verifica in corso…';
    const result = await api('/api/accesso', { method: 'POST', body: { frames } });
    if (result.esito === 'aperto') {
      showResult('aperto', 'Accesso consentito', 'Puoi proseguire.', result.tempi_ms?.endpoint);
    } else if (result.esito === 'negato') {
      showResult('negato', 'Accesso non consentito', 'Nessuna corrispondenza ammessa.', result.tempi_ms?.endpoint);
    } else {
      throw new Error('La risposta non è completa. Riprova tra poco.');
    }
  } catch (error) {
    showResult('error', 'Verifica non completata', error.message);
  } finally {
    setBusy(false);
  }
}

async function pollStatus(generation = pollGeneration) {
  if (leaving || generation !== pollGeneration) return;
  try {
    const status = await api('/api/stato', { timeout: 8000 });
    if (leaving || generation !== pollGeneration) return;
    serviceReady = Boolean(status.pronto);
    setConnection(byId('connection'), serviceReady);
    byId('service-notice').hidden = serviceReady;
    byId('service-notice').textContent = status.errore || 'Avvio del servizio in corso.';
  } catch {
    if (leaving || generation !== pollGeneration) return;
    serviceReady = false;
    setConnection(byId('connection'), false);
    byId('service-notice').textContent = 'Servizio non raggiungibile. Riconnessione in corso.';
    byId('service-notice').hidden = false;
  } finally {
    if (!leaving && generation === pollGeneration) {
      updateControls();
      pollTimer = setTimeout(function () { pollStatus(generation); }, 1800);
    }
  }
}

byId('start-camera').addEventListener('click', startCamera);
byId('reset-source').addEventListener('click', resetSource);
byId('choose-photos').addEventListener('click', function () { byId('photos').click(); });
byId('photos').addEventListener('change', choosePhotos);
byId('access').addEventListener('click', attemptAccess);
window.addEventListener('pagehide', function () {
  leaving = true;
  pollGeneration += 1;
  clearTimeout(pollTimer);
  camera.stop();
});
window.addEventListener('pageshow', function (event) {
  if (event.persisted) {
    leaving = false;
    resetSource();
    pollStatus();
  }
});
pollStatus();
