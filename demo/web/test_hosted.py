"""Hosted-origin checks over internal ASGI calls; no native processes or network."""
import os
import unittest
from unittest.mock import patch

from .app import create_app, normalize_public_origin
from .test_app import FakeEngines, FakeEnroller, image_frame, request


class PublicOriginTests(unittest.TestCase):
    def test_additional_origins_require_valid_https_and_hosted_mode(self):
        with patch.dict(os.environ, {"VARCO_WEB_PUBLIC_ORIGIN": "https://varco.example",
                                     "VARCO_WEB_ADDITIONAL_ORIGINS": "http://outside.example"}):
            with self.assertRaises(ValueError):
                create_app()
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                create_app(additional_origins=["https://second.example"])

    def test_origin_normalization_and_explicit_configuration(self):
        for original, expected in (
            ("https://Varco.example/", "https://varco.example"),
            ("https://varco.example:443", "https://varco.example"),
            ("https://varco.example:8443/", "https://varco.example:8443"),
            ("https://[::1]:8443", "https://[::1]:8443"),
        ):
            with self.subTest(original=original):
                self.assertEqual(normalize_public_origin(original), expected)
        with patch.dict(os.environ, {"VARCO_WEB_PUBLIC_ORIGIN": "https://from-env.example/"}):
            self.assertEqual(create_app().state.public_origin, "https://from-env.example")
            self.assertEqual(create_app(public_origin="https://explicit.example").state.public_origin,
                             "https://explicit.example")
        with patch.dict(os.environ, {"VARCO_WEB_PUBLIC_ORIGIN": ""}):
            with self.assertRaises(ValueError):
                create_app()

    def test_invalid_origins_fail_before_startup_without_echoing_input(self):
        for value in ("", "http://varco.example", "//varco.example", "https://",
                      "https://user:private@example.com", "https://varco.example/path",
                      "https://varco.example?", "https://varco.example#",
                      "https://varco.example:0", "https://varco.example:65536",
                      "https://varco.example:", "https://varco.example:bad",
                      "https://*.example", "https://-bad.example", "https://bad..example",
                      "https://varco.example\\outside", "https://varco.example%2foutside",
                      "https://varco.example\n", "https://varco.example\x00",
                      " https://varco.example", "https://vàrco.example", "https://[bad]",
                      "https://[::1]outside", "https://[::1]:"):
            with self.subTest(value=value), self.assertRaises(ValueError) as error:
                create_app(public_origin=value)
            self.assertEqual(str(error.exception),
                             "L'origine pubblica deve essere un URL HTTPS con solo host e porta opzionale.")


class HostedAppTests(unittest.IsolatedAsyncioTestCase):
    origin = "https://varco.example:8443"
    host = "varco.example:8443"

    async def asyncSetUp(self):
        self.engines, self.enroller = FakeEngines(), FakeEnroller()
        self.app = create_app(engines=self.engines, enroller=self.enroller, public_origin=self.origin)
        self.lifespan = self.app.router.lifespan_context(self.app)
        await self.lifespan.__aenter__()

    async def asyncTearDown(self):
        await self.lifespan.__aexit__(None, None, None)

    async def session(self):
        status, headers, _ = await request(self.app, "GET", "/api/stato", headers={"host": self.host})
        self.assertEqual(status, 200)
        cookie = headers["set-cookie"]
        for attribute in ("Secure", "HttpOnly", "SameSite=lax", "Path=/"):
            self.assertIn(attribute, cookie)
        self.assertNotIn("Domain=", cookie)
        return cookie.split(";", 1)[0]

    async def test_public_origin_over_internal_http_keeps_sessions_isolated(self):
        first, second = await self.session(), await self.session()
        self.assertNotEqual(first, second)
        status, _, body = await request(self.app, "POST", "/api/galleria", cookie=first,
                                       headers={"host": self.host, "origin": self.origin},
                                       payload={"nome": "Ada", "soglia": 273, "frames": [image_frame()[0]]})
        self.assertEqual(status, 201)
        identifier = body["iscritto"]["id"]
        self.assertEqual((await request(self.app, "GET", "/api/galleria", cookie=second,
                                       headers={"host": self.host}))[2]["totale"], 0)
        self.assertEqual((await request(self.app, "GET", "/api/foto/" + identifier, cookie=second,
                                       headers={"host": self.host}))[0], 404)
        self.assertEqual((await request(self.app, "GET", "/api/foto/" + identifier, cookie=first,
                                       headers={"host": self.host}))[0], 200)

    async def test_foreign_missing_and_proxy_supplied_origins_do_not_bypass_checks(self):
        cookie = await self.session()
        for override in ({"host": "outside.example"}, {"host": "127.0.0.1:8010"},
                         {"host": "varco.example"}, {"origin": "https://outside.example"},
                         {"origin": "http://varco.example:8443"}, {"origin": None},
                         {"sec-fetch-site": "same-site"}, {"sec-fetch-site": "cross-site"},
                         {"host": "outside.example", "x-forwarded-host": self.host,
                          "x-forwarded-proto": "https", "forwarded": "host=" + self.host}):
            headers = {"host": self.host, "origin": self.origin} | override
            with self.subTest(override=override):
                status, _, _ = await request(self.app, "POST", "/api/galleria", cookie=cookie,
                                             headers=headers, payload={"nome": "Ada", "soglia": 273,
                                                                       "frames": [image_frame()[0]]})
                self.assertEqual(status, 403)
        self.assertEqual(self.enroller.calls, 0)

    async def test_duplicate_host_or_origin_is_rejected_even_when_values_match(self):
        cookie = await self.session()
        for field, value in ((b"host", self.host), (b"origin", self.origin)):
            async def duplicate_header(scope, receive, send):
                scope = dict(scope, headers=[*scope["headers"], (field, value.encode())])
                await self.app(scope, receive, send)

            with self.subTest(field=field):
                status, _, _ = await request(duplicate_header, "POST", "/api/galleria", cookie=cookie,
                                             headers={"host": self.host, "origin": self.origin},
                                             payload={"nome": "Ada", "soglia": 273,
                                                      "frames": [image_frame()[0]]})
                self.assertEqual(status, 403)
        self.assertEqual(self.enroller.calls, 0)


class MultipleHostedOriginsTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_host_accepts_its_own_origin_and_rejects_cross_host_posts(self):
        first, second = "https://varco.example:8443", "https://second.example"
        with patch.dict(os.environ, {"VARCO_WEB_ADDITIONAL_ORIGINS": "https://Second.example:443/"}):
            app = create_app(engines=FakeEngines(), enroller=FakeEnroller(), public_origin=first)
        async with app.router.lifespan_context(app):
            cookies = []
            for origin, other in ((first, second), (second, first)):
                host = origin.removeprefix("https://")
                status, headers, _ = await request(app, "GET", "/api/stato", headers={"host": host})
                self.assertEqual(status, 200)
                self.assertIn("Secure", headers["set-cookie"])
                self.assertNotIn("Domain=", headers["set-cookie"])
                cookie = headers["set-cookie"].split(";", 1)[0]
                cookies.append(cookie)
                payload = {"nome": "Ada", "soglia": 273, "frames": [image_frame()[0]]}
                self.assertEqual((await request(app, "POST", "/api/galleria", cookie=cookie,
                                               headers={"host": host, "origin": other}, payload=payload))[0], 403)
                self.assertEqual((await request(app, "POST", "/api/galleria", cookie=cookie,
                                               headers={"host": host, "origin": origin}, payload=payload))[0], 201)
            self.assertNotEqual(*cookies)
            for host in ("outside.example", "127.0.0.1:8010"):
                self.assertEqual((await request(app, "GET", "/api/stato", headers={"host": host}))[0], 403)


if __name__ == "__main__":
    unittest.main()
