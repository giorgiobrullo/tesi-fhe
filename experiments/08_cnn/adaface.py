"""AdaFace IR101 (ResNet100-class) pre-addestrato, **frozen**, eseguito sul client.

Quarto modello di confronto del gradino 08 (oltre a MobileFaceNet / ResNet50 / ResNet100
di InsightFace). Linea AdaFace invece di ArcFace: stessa idea (embedding 512-dim
L2-normalizzato, volti allineati 112×112), margine adattivo alla qualità in addestramento.

- Backbone: IResNet `ir_101` (definizione classica da github.com/mk-minchul/AdaFace,
  file net.py, vendorizzata qui in `_adaface_net.py`). `build_model('ir_101')` →
  Backbone(input_size=(112,112), num_layers=100, mode='ir'). Il forward restituisce
  (embedding, norma) con l'embedding già L2-normalizzato.
- Pesi: checkpoint AdaFace IR101 addestrato su **WebFace12M**, ripreso dal repo CVLface
  dell'autore (HuggingFace `minchul/cvlface_adaface_ir101_webface12m`, file
  `model.safetensors`, ~249 MB). Le chiavi hanno prefisso `model.net.` da rimuovere:
  così combaciano 1:1 (917 tensori, 0 mismatch) con `ir_101` classico.

Preprocessing: input 112×112, normalizzato `(x-127.5)/127.5` = `(x/255-0.5)/0.5`,
layout NCHW; embedding finale L2-normalizzato. Ordine canali: il repo CVLface dichiara
nel suo `config.json` `color_space: RGB` (niente color-flip interno), quindi questi pesi
si alimentano in **RGB** (default `bgr=False`). NB: l'AdaFace "classico" da `.ckpt` su
Drive vuole invece BGR; sul sintetico DigiFace entrambi superano comodamente la soglia
(RGB acc 98.93% d'=4.98, BGR acc 98.67% d'=4.64), RGB leggermente meglio e fedele al repo.

Gira in chiaro sul client (fidato): il modello non tocca il costo FHE, conta solo la
dimensione dell'embedding (512), identica agli altri. Pesi gitignorati sotto datasets/.
"""

import importlib.util
import os

import numpy as np
import torch

_DIR = os.path.dirname(os.path.abspath(__file__))
_PESI = os.path.join(_DIR, "..", "..", "datasets", "adaface",
                     "cvlface_adaface_ir101_webface12m.safetensors")
_cache: dict = {}


def _device() -> str:
    return "mps" if torch.backends.mps.is_available() else "cpu"


def _net_module():
    """Importa la definizione IResNet vendorizzata (net.py classico di AdaFace)."""
    spec = importlib.util.spec_from_file_location(
        "_adaface_net", os.path.join(_DIR, "_adaface_net.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def carica(pesi: str | None = None):
    """Carica (una volta) il backbone ir_101 con i pesi AdaFace WebFace12M, in eval."""
    if "modello" not in _cache:
        from safetensors.torch import load_file
        raw = load_file(pesi or _PESI)
        # CVLface incapsula il backbone: chiavi 'model.net.<…>' → togli il prefisso.
        sd = {}
        for k, v in raw.items():
            for pre in ("model.net.", "net.", "model."):
                if k.startswith(pre):
                    k = k[len(pre):]
                    break
            sd[k] = v
        model = _net_module().build_model("ir_101")
        info = model.load_state_dict(sd, strict=True)   # deve combaciare esattamente
        model.eval().to(_device())
        _cache["modello"] = model
        _cache["info"] = info
    return _cache["modello"]


@torch.no_grad()
def embedding_adaface(immagini_rgb_uint8: np.ndarray, bgr: bool = False,
                      batch: int = 256) -> np.ndarray:
    """(N,112,112,3) RGB uint8 (volti già allineati) → (N,512) L2-normalizzato.

    `bgr=False` (default, fedele al repo CVLface: color_space=RGB): RGB poi
    (x-127.5)/127.5. `bgr=True` applica RGB→BGR (preprocessing AdaFace classico da
    .ckpt) — passa anch'esso la validazione, ma leggermente sotto.
    """
    model = carica()
    dev = _device()
    x = np.asarray(immagini_rgb_uint8)
    if x.ndim == 3:
        x = x[None]
    if x.shape[-1] == 4:                       # RGBA → RGB
        x = x[..., :3]
    # conversione float + normalizzazione + transpose PER BLOCCO: farlo sull'intero array in
    # un colpo (su 500k img sono ~150 GB di picco) manda in OOM. Per blocco tiene ~38 MB.
    out = []
    for i in range(0, len(x), batch):
        b = x[i:i + batch].astype(np.float32)
        if bgr:
            b = b[..., ::-1]                   # RGB → BGR
        b = (b - 127.5) / 127.5                # → [-1, 1]
        b = np.ascontiguousarray(b.transpose(0, 3, 1, 2))   # NHWC → NCHW
        t = torch.from_numpy(b).to(dev)
        feat, _ = model(t)                     # forward → (embedding, norma)
        out.append(feat.float().cpu().numpy())
    E = np.vstack(out) if out else np.empty((0, 512), np.float32)
    return E / (np.linalg.norm(E, axis=1, keepdims=True) + 1e-9)
