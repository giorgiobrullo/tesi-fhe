"""Default portraits use real enrollment and remain independent across sessions."""
import asyncio
import copy
import hashlib
import json
import tempfile
import unittest
import uuid
from pathlib import Path

from .app import create_app
from .default_gallery import prepare_gallery
from .test_app import FakeEngines, FakeEnroller, image_frame, request


class DefaultGalleryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        photo = image_frame()[1]
        (self.root / "face.jpg").write_bytes(photo)
        self.person = {"slug": "example", "nome": "Example", "soglia": 273,
                       "foto": "face.jpg", "sha256": hashlib.sha256(photo).hexdigest(),
                       "nota": "An example", "crediti": {"autore": "Test"}}
        self.write_catalogue([self.person])

    def write_catalogue(self, entries):
        (self.root / "catalogue.json").write_text(json.dumps(entries))

    async def test_defaults_are_independent_and_use_original_photo_for_probe(self):
        enroller = FakeEnroller()
        seeds = prepare_gallery(enroller, self.root)
        self.assertEqual(enroller.calls, 1)
        identifier = seeds.entries[0]["id"]
        self.assertEqual(seeds.photos[identifier], (self.root / "face.jpg").read_bytes())
        engines = FakeEngines()
        app = create_app(engines=engines, enroller=enroller, default_gallery=seeds)
        async with app.router.lifespan_context(app):
            async def session():
                response = await request(app, "GET", "/api/stato")
                return response[1]["set-cookie"].split(";", 1)[0]

            first, second = await session(), await session()
            entries = (await request(app, "GET", "/api/galleria", cookie=first))[2]["iscritti"]
            self.assertTrue(entries[0]["esempio"])
            self.assertEqual(entries[0]["crediti"]["autore"], "Test")
            self.assertNotIn("vettore", entries[0])
            first_session, second_session = list(app.state.service.sessions.values())
            # The immutable seed templates are shared; mutations must copy their containers.
            self.assertIs(first_session.entries, second_session.entries)
            self.assertIs(first_session.photos, second_session.photos)
            response = await request(app, "PATCH", "/api/galleria/" + identifier, cookie=first,
                                     payload={"nome": "Edited", "soglia": -100})
            self.assertTrue(response[2]["iscritto"]["esempio"])
            await request(app, "DELETE", "/api/galleria/" + identifier, cookie=first)
            self.assertEqual((await request(app, "GET", "/api/foto/" + identifier, cookie=first))[0], 404)
            self.assertEqual((await request(app, "GET", "/api/foto/" + identifier, cookie=second))[0], 200)
            third = await session()
            for cookie in (second, third):
                entry = (await request(app, "GET", "/api/galleria", cookie=cookie))[2]["iscritti"][0]
                self.assertEqual((entry["nome"], entry["soglia"]), ("Example", 273))
            original_vector = list(seeds.entries[0]["vettore"])
            engines.mutate = True
            await request(app, "POST", "/api/accesso", cookie=second,
                          payload={"frames": [image_frame()[0]], "motore": "attuale"})
            await asyncio.wait_for(app.state.service.queue.join(), 2)
            self.assertEqual(enroller.calls, 2)  # No enrollment repeated for each new visitor.
            self.assertEqual([c[0] for c in engines.calls], ["attuale"])
            self.assertEqual(seeds.entries[0]["vettore"], original_vector)
            self.assertEqual(second_session.entries[0]["vettore"], original_vector)
            self.assertEqual((await request(app, "GET", "/api/galleria", cookie=third))[2]["iscritti"][0]["nome"], "Example")

    def test_modified_source_and_duplicate_vectors_are_rejected(self):
        (self.root / "face.jpg").write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "modificata"):
            prepare_gallery(FakeEnroller(), self.root)
        (self.root / "face.jpg").write_bytes(image_frame()[1])
        self.write_catalogue([self.person, self.person | {"slug": "other", "nome": "Other"}])
        with self.assertRaisesRegex(ValueError, "stesso template"):
            prepare_gallery(FakeEnroller(), self.root)

    def test_template_must_also_fit_query_domain(self):
        enroller = FakeEnroller()
        enroller.vector = [3] * 512
        with self.assertRaisesRegex(ValueError, "supera il dominio"):
            prepare_gallery(enroller, self.root)

    def test_catalogue_capacity_is_checked_before_preparation(self):
        enroller = FakeEnroller()
        for entries in ([], [self.person] * 129):
            self.write_catalogue(entries)
            with self.assertRaisesRegex(ValueError, "da 1 a 128"):
                prepare_gallery(enroller, self.root)
        self.assertEqual(enroller.calls, 0)

    async def test_large_gallery_leaves_room_for_personal_entries_and_checks_full_snapshot(self):
        enroller = FakeEnroller()
        seeds = prepare_gallery(enroller, self.root)
        template = seeds.entries[0]
        seeds.entries = []
        for i in range(120):
            entry = copy.deepcopy(template)
            entry.update(id=str(uuid.uuid4()), nome=f"Person {i + 1}")
            entry["foto_file"] = entry["id"] + ".jpg"
            seeds.entries.append(entry)
        engines = FakeEngines()
        app = create_app(engines=engines, enroller=enroller, default_gallery=seeds)
        async with app.router.lifespan_context(app):
            async def session():
                response = await request(app, "GET", "/api/stato")
                self.assertEqual(response[2]["iscritti"], 120)
                return response[1]["set-cookie"].split(";", 1)[0]

            first, second = await session(), await session()
            payload = {"nome": "Added person", "soglia": 273, "frames": [image_frame()[0]]}
            response = await request(app, "POST", "/api/galleria", cookie=first, payload=payload)
            self.assertEqual((response[0], response[2]["totale"]), (201, 121))
            await request(app, "POST", "/api/accesso", cookie=first,
                          payload={"frames": [image_frame()[0]], "motore": "attuale"})
            await asyncio.wait_for(app.state.service.queue.join(), 2)
            self.assertEqual([len(call[2]) for call in engines.calls], [121])
            self.assertEqual(engines.calls[0][2][-1]["nome"], "Added person")
            row = (await request(app, "GET", "/api/richieste", cookie=first))[2]["richieste"][0]
            self.assertEqual(row["iscritti"], 121)
            for _ in range(7):
                self.assertEqual((await request(app, "POST", "/api/galleria", cookie=first, payload=payload))[0], 201)
            self.assertEqual((await request(app, "POST", "/api/galleria", cookie=first, payload=payload))[0], 409)
            self.assertEqual((await request(app, "GET", "/api/galleria", cookie=first))[2]["totale"], 128)
            self.assertEqual((await request(app, "GET", "/api/galleria", cookie=second))[2]["totale"], 120)


if __name__ == "__main__":
    unittest.main()
