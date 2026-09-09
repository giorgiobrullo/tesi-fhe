export const FRAME_COUNT = 3;

const ICON_PATHS = {
  camera: '<path d="M14.5 4h-5L8 7H4a2 2 0 0 0-2 2v10h20V9a2 2 0 0 0-2-2h-4z"/><circle cx="12" cy="13" r="3.5"/>',
  upload: '<path d="M12 16V3m-4 4 4-4 4 4M4 14v6h16v-6"/>',
  arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>',
  external: '<path d="M14 3h7v7m0-7L10 14M10 3H3v18h18v-7"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
  people: '<circle cx="9" cy="8" r="3"/><path d="M3 21v-3a6 6 0 0 1 12 0v3m1-17a3 3 0 0 1 0 6m3 11v-3a6 6 0 0 0-3-5"/>',
  pulse: '<path d="M2 12h5l3-8 4 16 3-8h5"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  edit: '<path d="m15 4 5 5M4 20l5-1L21 7a2.1 2.1 0 0 0-4-4L5 15z"/>',
  trash: '<path d="M3 6h18M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7m4-7v7"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  image: '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8" cy="8" r="1"/><path d="m3 17 5-5 4 4 4-6 5 7"/>',
};

export function icon(name) {
  const element = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  element.setAttribute('viewBox', '0 0 24 24');
  element.setAttribute('fill', 'none');
  element.setAttribute('stroke', 'currentColor');
  element.setAttribute('stroke-width', '1.65');
  element.setAttribute('stroke-linecap', 'round');
  element.setAttribute('stroke-linejoin', 'round');
  element.setAttribute('aria-hidden', 'true');
  element.innerHTML = ICON_PATHS[name] || ICON_PATHS.image;
  return element;
}

export function mountIcons() {
  for (const element of document.querySelectorAll('[data-icon]')) {
    element.replaceChildren(icon(element.dataset.icon));
  }
}

export async function api(path, { method = 'GET', body, timeout = 180000 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(function () { controller.abort(); }, timeout);
  try {
    const options = { method, signal: controller.signal, credentials: 'same-origin', cache: 'no-store' };
    if (body !== undefined) {
      options.headers = { 'Content-Type': 'application/json' };
      options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    const result = await response.json().catch(function () { return {}; });
    if (!response.ok) {
      const message = result.errore || result.detail || result.message;
      throw new Error(typeof message === 'string' ? message : 'Il servizio non ha completato la richiesta. Riprova.');
    }
    return result;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('La richiesta sta impiegando troppo tempo. Verifica la connessione e riprova.');
    if (error instanceof TypeError) throw new Error('Il servizio non è raggiungibile. Riprova tra poco.');
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export function setConnection(element, ready, label) {
  element.dataset.state = ready ? 'ready' : 'offline';
  element.querySelector('span').textContent = label || (ready ? 'Pronto' : 'Non disponibile');
}

export function duration(milliseconds) {
  if (!Number.isFinite(milliseconds)) return '—';
  if (milliseconds < 1000) return `${Math.round(milliseconds)} ms`;
  return `${(milliseconds / 1000).toLocaleString('it-IT', { maximumFractionDigits: 2, minimumFractionDigits: 1 })} s`;
}

function delay(milliseconds) {
  return new Promise(function (resolve) { setTimeout(resolve, milliseconds); });
}

function encodeImage(source, width, height) {
  const ratio = Math.min(1, 1280 / Math.max(width, height));
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, Math.round(width * ratio));
  canvas.height = Math.max(1, Math.round(height * ratio));
  const context = canvas.getContext('2d');
  context.drawImage(source, 0, 0, canvas.width, canvas.height);
  return canvas.toDataURL('image/jpeg', .9);
}

export async function readPhotos(fileList) {
  const files = Array.from(fileList);
  if (!files.length || files.length > FRAME_COUNT) throw new Error('Scegli da una a tre foto.');
  const frames = [];
  for (const file of files) {
    if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) {
      throw new Error('Usa foto in formato JPG, PNG o WebP.');
    }
    if (file.size > 20 * 1024 * 1024) throw new Error('Una foto è troppo grande. Scegli file inferiori a 20 MB.');
    const objectURL = URL.createObjectURL(file);
    try {
      const photo = new Image();
      photo.src = objectURL;
      await photo.decode();
      if (!photo.naturalWidth || !photo.naturalHeight) throw new Error('Non è stato possibile leggere una delle foto.');
      frames.push(encodeImage(photo, photo.naturalWidth, photo.naturalHeight));
    } catch {
      throw new Error('Non è stato possibile leggere una delle foto. Scegli un’altra immagine.');
    } finally {
      URL.revokeObjectURL(objectURL);
    }
  }
  return frames;
}

export class Camera {
  constructor(video) {
    this.video = video;
    this.stream = null;
    this.generation = 0;
  }

  get active() {
    return Boolean(this.stream && this.stream.getVideoTracks().some(function (track) { return track.readyState === 'live'; }));
  }

  async start() {
    if (!navigator.mediaDevices?.getUserMedia) throw new Error('La fotocamera non è disponibile in questo browser. Puoi caricare una foto.');
    this.stop();
    const generation = this.generation;
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 960 } }, audio: false });
      if (generation !== this.generation) {
        stream.getTracks().forEach(function (track) { track.stop(); });
        return false;
      }
      this.stream = stream;
      this.video.srcObject = stream;
      await this.video.play();
      return true;
    } catch (error) {
      if (stream) stream.getTracks().forEach(function (track) { track.stop(); });
      if (this.stream === stream) this.stream = null;
      if (generation !== this.generation) return false;
      if (error.name === 'NotAllowedError') throw new Error('Consenti l’uso della fotocamera nel browser, oppure carica una foto.');
      if (error.name === 'NotFoundError') throw new Error('Non è stata trovata una fotocamera. Puoi caricare una foto.');
      throw new Error('Non riesco ad aprire la fotocamera. Verifica che non sia in uso in un’altra applicazione.');
    }
  }

  stop() {
    this.generation += 1;
    if (this.stream) this.stream.getTracks().forEach(function (track) { track.stop(); });
    this.stream = null;
    this.video.srcObject = null;
  }

  async capture(onProgress = function () {}) {
    if (!this.active || !this.video.videoWidth) throw new Error('La fotocamera non è ancora pronta. Attendi un momento e riprova.');
    const frames = [];
    for (let index = 0; index < FRAME_COUNT; index += 1) {
      if (!this.active) throw new Error('La fotocamera si è interrotta. Riattivala e riprova.');
      frames.push(encodeImage(this.video, this.video.videoWidth, this.video.videoHeight));
      onProgress(index + 1, FRAME_COUNT);
      if (index + 1 < FRAME_COUNT) await delay(220);
    }
    return frames;
  }
}

export function renderPreviews(container, frames) {
  container.replaceChildren();
  frames.forEach(function (frame, index) {
    const image = document.createElement('img');
    image.src = frame;
    image.alt = `Foto selezionata ${index + 1}`;
    container.append(image);
  });
}

export function galleryPhotoURL(value) {
  if (!value) return null;
  try {
    const url = new URL(value, location.origin);
    if (url.origin !== location.origin || !/^\/api\/foto\/[a-zA-Z0-9-]+$/.test(url.pathname)) return null;
    return url.href;
  } catch { return null; }
}
