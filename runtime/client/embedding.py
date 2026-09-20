"""Client-local face alignment, embedding, fusion and quantization."""
import base64
import importlib.util
import io
import time

import numpy as np


class FaceEmbedding:
    def __init__(self, config, assets, log):
        self.config = config
        self.assets = assets
        self.log = log
        self._model = None

    @property
    def loaded(self):
        return self._model is not None

    def modello(self):
        if self._model is None:
            path = self.assets / "experiments/08_cnn/embedding.py"
            spec = importlib.util.spec_from_file_location("varco_face_embedding", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.log("carico ResNet100 (in chiaro, sul client)...")
            module.carica(self.config["modello"])
            self._model = module
        return self._model

    def da_dataurl(self, d):
        import imageio.v2 as imageio

        return imageio.imread(io.BytesIO(base64.b64decode(d.split(",", 1)[1])))[..., :3]

    def allinea(self, frames_rgb):
        """Rileva e allinea sui 5 landmark, tenendo il volto piu' grande (chi e' davanti al varco).

        Il rilevatore e' quello di buffalo_s: l'allineamento e' lo stesso template canonico per tutti i
        modelli ArcFace, quindi si puo' usare un rilevatore leggero e poi l'embedding col modello scelto
        (e' esattamente quello che fa la pipeline dei benchmark, che allinea una volta e riusa i crop).
        Torna None se in nessun frame c'e' un volto."""
        from insightface.utils import face_align

        ec = self.modello()
        det = ec._app("mobilefacenet")
        out = []
        for im in frames_rgb:
            bgr = im[..., ::-1]
            boxes, landmarks = det.det_model.detect(bgr, max_num=0, metric="default")
            if len(boxes):
                index = max(range(len(boxes)), key=lambda i:
                            (boxes[i, 2] - boxes[i, 0]) * (boxes[i, 3] - boxes[i, 1]))
                out.append(face_align.norm_crop(bgr, landmarks[index])[..., ::-1])
        return np.array(out) if out else None

    def embedding_fuso(self, frames_rgb, gia_allineati=False):
        """Multi-frame (F48): allinea, embedda, media, L2. Torna (vettore quantizzato, dettagli)."""
        ec = self.modello()
        t0 = time.perf_counter()
        X = np.array(frames_rgb) if gia_allineati else self.allinea(frames_rgb)
        if X is None:
            raise ValueError("nessun volto rilevato: inquadra il viso e riprova")
        E = ec.embedding(X, self.config["modello"])
        t_emb = (time.perf_counter() - t0) * 1000
        v = E.mean(0)
        v = v / (np.linalg.norm(v) + 1e-9)
        qm = self.config["q_max"]
        q = np.clip(np.round(v / self.config["scala"]), -qm, qm).astype(int)
        return q, {"frame": len(X), "embedding_ms": round(t_emb, 1)}
