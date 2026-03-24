import unittest
from unittest.mock import patch
import json
import time
import shutil
import tempfile
import os

import requests

import osint_engine


class FakeResponse:
    def __init__(self, status_code=200, url="https://example.com", text="", headers=None, json_data=None):
        self.status_code = status_code
        self.url = url
        self.text = text
        self.headers = headers or {}
        self.cookies = []
        self._json_data = json_data or {}

    def __bool__(self):
        return self.status_code < 400

    def json(self):
        return self._json_data


class FakeAnswer:
    def __init__(self, text, preference=None, exchange=None):
        self.text = text
        self.preference = preference
        self.exchange = exchange

    def __str__(self):
        return self.text


class FakeResolver:
    def __init__(self, answers=None, failures=None):
        self.answers = answers or {}
        self.failures = failures or set()
        self.timeout = None
        self.lifetime = None
        self.nameservers = []

    def resolve(self, name, rtype):
        key = (name, rtype)
        if key in self.failures:
            raise osint_engine.dns.resolver.LifetimeTimeout(timeout=5)
        return self.answers.get(key, [])


class OsintEngineTests(unittest.TestCase):
    def test_merge_provider_results_keeps_duplicate_details_under_each_provider(self):
        provider_results = {}

        osint_engine.record_provider_result(provider_results, "rocketreach", "emails", ["alice@example.com"])
        osint_engine.record_provider_result(provider_results, "hunter", "emails", ["alice@example.com"])

        self.assertEqual(provider_results["rocketreach"]["emails"], ["alice@example.com"])
        self.assertEqual(provider_results["hunter"]["emails"], ["alice@example.com"])

    def test_finalize_provider_result_marks_skipped_provider_with_note(self):
        provider_results = {}

        osint_engine.mark_provider_skipped(provider_results, "rocketreach", "API key not configured")

        self.assertEqual(provider_results["rocketreach"]["status"], "skipped")
        self.assertIn("API key not configured", provider_results["rocketreach"]["notes"])

    def test_provider_notes_do_not_duplicate_same_message(self):
        provider_results = {}

        osint_engine.record_provider_note(provider_results, "rocketreach", "No matching emails found")
        osint_engine.record_provider_note(provider_results, "rocketreach", "No matching emails found")

        self.assertEqual(provider_results["rocketreach"]["notes"], ["No matching emails found"])

    def test_source_enabled_defaults_to_true_when_no_selection_is_configured(self):
        with patch.dict(os.environ, {}, clear=False):
            self.assertTrue(osint_engine.source_enabled("hunter"))
            self.assertTrue(osint_engine.source_enabled("shodan"))

    def test_source_enabled_reads_selected_provider_ids_from_environment(self):
        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["duckduckgo", "crtsh", "theharvester"]'},
            clear=False,
        ):
            self.assertTrue(osint_engine.source_enabled("duckduckgo"))
            self.assertFalse(osint_engine.source_enabled("hunter"))

    def test_which_uses_shutil_lookup(self):
        with patch("osint_engine.shutil.which", return_value=r"C:\\tool\\theHarvester.exe") as mocked:
            result = osint_engine._which("theHarvester")

        self.assertEqual(result, r"C:\\tool\\theHarvester.exe")
        mocked.assert_called_once_with("theHarvester")

    def test_which_falls_back_to_current_python_scripts_directory(self):
        with patch("osint_engine.shutil.which", return_value=None):
            with patch("osint_engine.sys.executable", r"C:\\repo\\.venv\\Scripts\\python.exe"):
                with patch(
                    "osint_engine.os.path.exists",
                    side_effect=lambda path: path.endswith("theHarvester.exe"),
                ):
                    result = osint_engine._which("theHarvester")

        self.assertEqual(result, r"C:\\repo\\.venv\\Scripts\\theHarvester.exe")

    def test_run_recon_ng_uses_system_temp_directory_for_resource_script(self):
        class FakeCompleted:
            def __init__(self):
                self.stdout = "alice@example.com"
                self.stderr = ""

        written = {}

        def fake_open(path, mode="r", *args, **kwargs):
            written["path"] = path

            class DummyFile:
                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, exc_type, exc, tb):
                    return False

                def write(self_inner, content):
                    written["content"] = content

            return DummyFile()

        with patch("osint_engine._which", return_value="recon-ng.exe"):
            with patch("osint_engine.tempfile.gettempdir", return_value=r"C:\\Temp"):
                with patch("osint_engine.open", side_effect=fake_open):
                    with patch("osint_engine.subprocess.run", return_value=FakeCompleted()) as mocked_run:
                        osint_engine.run_recon_ng("example.com")

        self.assertEqual(written["path"], r"C:\\Temp\\recon_ng_script.rc")
        mocked_run.assert_called_once()

    def test_run_theharvester_uses_system_temp_directory_for_output_files(self):
        class FakeCompleted:
            def __init__(self):
                self.stdout = "contact@example.com"
                self.stderr = ""

        with patch("osint_engine._which", return_value="theHarvester.exe"):
            with patch("osint_engine.tempfile.gettempdir", return_value=r"C:\\Temp"):
                with patch("osint_engine.subprocess.run", return_value=FakeCompleted()) as mocked_run:
                    with patch("osint_engine.open", side_effect=OSError()):
                        osint_engine.run_theharvester("example.com")

        args = mocked_run.call_args[0][0]
        self.assertIn(r"C:\\Temp\\harvester_out", args)

    def test_run_theharvester_records_only_its_own_provider_error(self):
        provider_results = {}

        with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["theharvester"]'}, clear=False):
            with patch("osint_engine._which", return_value="theHarvester.exe"):
                with patch("osint_engine.subprocess.run", side_effect=RuntimeError("boom")):
                    osint_engine.run_theharvester("example.com", provider_results)

        self.assertEqual(provider_results["theharvester"]["status"], "error")
        self.assertIn("boom", provider_results["theharvester"]["notes"])
        self.assertNotIn("recon_ng", provider_results)

    def test_run_recon_ng_marks_provider_error_on_unexpected_failure(self):
        provider_results = {}

        with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["recon_ng"]'}, clear=False):
            with patch("osint_engine._which", return_value="recon-ng.exe"):
                with patch("osint_engine.open", side_effect=RuntimeError("write failed")):
                    osint_engine.run_recon_ng("example.com", provider_results)

        self.assertEqual(provider_results["recon_ng"]["status"], "error")
        self.assertIn("write failed", provider_results["recon_ng"]["notes"])

    def test_run_emailharvest_passive_skips_hunter_when_not_selected(self):
        requested_urls = []

        def fake_safe_get(url, **kwargs):
            requested_urls.append(url)
            raise AssertionError(f"unexpected fetch: {url}")

        with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["duckduckgo"]'}, clear=False):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                with patch("osint_engine.log"):
                    emails = osint_engine.run_emailharvest_passive("example.com")

        self.assertEqual(emails, set())
        self.assertFalse(any("hunter.io" in url for url in requested_urls))

    def test_run_emailharvest_passive_skips_brave_when_key_is_missing(self):
        provider_results = {}

        with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["brave"]'}, clear=False):
            emails = osint_engine.run_emailharvest_passive("example.com", provider_results)

        self.assertEqual(emails, set())
        self.assertEqual(provider_results["brave"]["status"], "skipped")

    def test_run_emailharvest_passive_collects_brave_emails(self):
        provider_results = {}

        def fake_safe_get(url, **kwargs):
            if "api.search.brave.com" in url:
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "web": {
                            "results": [
                                {
                                    "url": "https://example.com/contact",
                                    "title": "Contact Example",
                                    "description": "Reach us at press@example.com",
                                }
                            ]
                        }
                    },
                )
            return FakeResponse(status_code=404)

        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["brave"]', "BRAVE_SEARCH_API_KEY": "brave-test-key"},
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                emails = osint_engine.run_emailharvest_passive("example.com", provider_results)

        self.assertEqual(emails, {"press@example.com"})
        self.assertEqual(provider_results["brave"]["emails"], ["press@example.com"])

    def test_run_emailharvest_passive_records_brave_mentions(self):
        provider_results = {}

        def fake_safe_get(url, **kwargs):
            if "api.search.brave.com" in url:
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "web": {
                            "results": [
                                {
                                    "url": "https://news.example.org/story-about-example",
                                    "title": "Example domain featured",
                                    "description": "Coverage of example.com operations and history",
                                }
                            ]
                        }
                    },
                )
            return FakeResponse(status_code=404)

        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["brave"]', "BRAVE_SEARCH_API_KEY": "brave-test-key"},
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                osint_engine.run_emailharvest_passive("example.com", provider_results)

        self.assertEqual(
            provider_results["brave"]["mentions"],
            [
                {
                    "category": "news",
                    "title": "Example domain featured",
                    "url": "https://news.example.org/story-about-example",
                    "snippet": "Coverage of example.com operations and history",
                    "source_domain": "news.example.org",
                    "matched_domain": "example.com",
                    "query": '"example.com"',
                }
            ],
        )

    def test_classify_search_mention_marks_forum_hits(self):
        mention = osint_engine.classify_search_mention(
            {
                "url": "https://www.reddit.com/r/osint/comments/123/example_domain/",
                "title": "Thread about example.com",
                "description": "Forum users discussing example.com",
            },
            "example.com",
            '"example.com"',
        )

        self.assertEqual(mention["category"], "forum")
        self.assertEqual(mention["source_domain"], "reddit.com")

    def test_run_rocketreach_skips_when_key_is_missing(self):
        env = dict(os.environ)
        env["OSINT_SELECTED_SOURCES"] = '["rocketreach"]'
        env.pop("ROCKETREACH_API_KEY", None)

        with patch.dict(os.environ, env, clear=True):
            emails = osint_engine.run_rocketreach("example.com", "Example")

        self.assertEqual(emails, set())

    def test_run_rocketreach_returns_domain_matching_emails_when_selected_and_configured(self):
        class FakeLookup:
            @staticmethod
            def search(**kwargs):
                return {
                    "profiles": [
                        {"current_work_email": "alice@example.com"},
                        {"current_work_email": "bob@other.com"},
                        {"emails": [{"email": "carol@example.com"}]},
                    ]
                }

        with patch.dict(
            os.environ,
            {
                "OSINT_SELECTED_SOURCES": '["rocketreach"]',
                "ROCKETREACH_API_KEY": "rr-test-key",
            },
            clear=False,
        ):
            with patch.object(osint_engine, "RocketReachAPI", FakeLookup, create=True):
                emails = osint_engine.run_rocketreach("example.com", "Example")

        self.assertEqual(emails, {"alice@example.com", "carol@example.com"})

    def test_run_rocketreach_uses_domain_aware_company_variants(self):
        observed_queries = []

        class FakeLookup:
            @staticmethod
            def search(**kwargs):
                observed_queries.append(kwargs["company_name"])
                if kwargs["company_name"] == "example.com":
                    return {"profiles": [{"current_work_email": "owner@example.com"}]}
                return {"profiles": []}

        with patch.dict(
            os.environ,
            {
                "OSINT_SELECTED_SOURCES": '["rocketreach"]',
                "ROCKETREACH_API_KEY": "rr-test-key",
            },
            clear=False,
        ):
            with patch.object(osint_engine, "RocketReachAPI", FakeLookup, create=True):
                emails = osint_engine.run_rocketreach("example.com", "Example Holdings")

        self.assertEqual(emails, {"owner@example.com"})
        self.assertIn("Example Holdings", observed_queries)
        self.assertIn("example.com", observed_queries)

    def test_run_emailharvest_passive_uses_github_token_when_configured(self):
        observed_headers = []

        def fake_safe_get(url, **kwargs):
            if "api.github.com/search/code" in url:
                observed_headers.append(kwargs.get("headers", {}))
                return FakeResponse(status_code=401, text='{"message":"Requires authentication"}')
            return FakeResponse(status_code=404)

        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["github_code"]', "GITHUB_TOKEN": "gh-test-token"},
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                provider_results = {}
                osint_engine.run_emailharvest_passive("example.com", provider_results)

        self.assertEqual(observed_headers[0]["Authorization"], "Bearer gh-test-token")

    def test_hibp_api_headers_use_existing_env_name_and_user_agent(self):
        with patch.dict(
            os.environ,
            {"HaveIBeenPwned_API_KEY": "hibp-existing-key"},
            clear=False,
        ):
            headers = osint_engine.hibp_api_headers()

        self.assertEqual(headers["hibp-api-key"], "hibp-existing-key")
        self.assertIn("User-Agent", headers)

    def test_harvest_emails_uses_hibp_api_key_when_configured(self):
        observed_headers = []

        def fake_safe_get(url, **kwargs):
            if "haveibeenpwned.com/api/v3/subscribeddomains" in url:
                observed_headers.append(kwargs.get("headers", {}))
                return FakeResponse(status_code=200, json_data=[{"DomainName": "example.com"}])
            if "haveibeenpwned.com/api/v3/breacheddomain/" in url:
                observed_headers.append(kwargs.get("headers", {}))
                return FakeResponse(status_code=200, json_data=[])
            return None

        with patch("osint_engine.run_theharvester", return_value=set()):
            with patch("osint_engine.run_recon_ng", return_value=set()):
                with patch("osint_engine.run_rocketreach", return_value=set()):
                    with patch("osint_engine.run_emailharvest_passive", return_value=set()):
                        with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                            with patch("osint_engine.discover_social_profiles", return_value={}):
                                with patch.dict(
                                    os.environ,
                                    {"OSINT_SELECTED_SOURCES": '["hibp"]', "HaveIBeenPwned_API_KEY": "hibp-test-key"},
                                    clear=False,
                                ):
                                    osint_engine.harvest_emails("example.com", "Example")

        self.assertEqual(observed_headers[0]["hibp-api-key"], "hibp-test-key")
        self.assertEqual(observed_headers[1]["hibp-api-key"], "hibp-test-key")

    def test_check_breaches_uses_hibp_api_key_when_configured(self):
        observed_headers = []

        def fake_safe_get(url, **kwargs):
            if "haveibeenpwned.com/api/v3/subscribeddomains" in url:
                observed_headers.append(kwargs.get("headers", {}))
                return FakeResponse(status_code=200, json_data=[{"DomainName": "example.com"}])
            if "haveibeenpwned.com/api/v3/breacheddomain/" in url:
                observed_headers.append(kwargs.get("headers", {}))
                return FakeResponse(status_code=200, json_data=[])
            return None

        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["hibp"]', "HaveIBeenPwned_API_KEY": "hibp-test-key"},
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                osint_engine.check_breaches("example.com", [], {})

        self.assertEqual(observed_headers[0]["hibp-api-key"], "hibp-test-key")
        self.assertEqual(observed_headers[1]["hibp-api-key"], "hibp-test-key")

    def test_hibp_reports_unverified_domain_when_key_is_valid(self):
        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["hibp"]', "HaveIBeenPwned_API_KEY": "hibp-test-key"},
            clear=False,
        ):
            with patch(
                "osint_engine.safe_get",
                return_value=FakeResponse(status_code=200, json_data=[{"DomainName": "verified.com"}]),
            ):
                provider_results = {}
                osint_engine.check_breaches("example.com", [], provider_results)

        self.assertIn(
            "API key is valid, but example.com is not a verified/subscribed HIBP domain",
            provider_results["hibp"]["notes"],
        )

    def test_hibp_reports_invalid_api_key_from_subscription_check(self):
        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["hibp"]', "HaveIBeenPwned_API_KEY": "hibp-test-key"},
            clear=False,
        ):
            with patch(
                "osint_engine.safe_get",
                return_value=FakeResponse(status_code=401, text='{"message":"Invalid API key"}'),
            ):
                provider_results = {}
                osint_engine.check_breaches("example.com", [], provider_results)

        self.assertIn("HIBP rejected the configured API key", provider_results["hibp"]["notes"])

    def test_run_emailharvest_passive_uses_existing_hunter_env_names_for_authenticated_api(self):
        observed_urls = []

        def fake_safe_get(url, **kwargs):
            if "api.hunter.io/v2/domain-search" in url:
                observed_urls.append(url)
                return FakeResponse(status_code=200, json_data={"data": {"emails": []}})
            return FakeResponse(status_code=404)

        with patch.dict(
            os.environ,
            {
                "OSINT_SELECTED_SOURCES": '["hunter"]',
                "Hunter_API_KEY": "hunter-existing-key",
            },
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                osint_engine.run_emailharvest_passive("example.com", {})

        self.assertIn("api_key=hunter-existing-key", observed_urls[0])

    def test_hunter_retries_with_hunterio_key_after_primary_401(self):
        observed_urls = []

        def fake_safe_get(url, **kwargs):
            if "api.hunter.io/v2/domain-search" in url:
                observed_urls.append(url)
                if "api_key=primary-key" in url:
                    return FakeResponse(status_code=401, text='{"errors":[{"details":"Unauthorized"}]}')
                if "api_key=secondary-key" in url:
                    return FakeResponse(status_code=200, json_data={"data": {"emails": [{"value": "alice@example.com"}]}})
            return FakeResponse(status_code=404)

        with patch.dict(
            os.environ,
            {
                "OSINT_SELECTED_SOURCES": '["hunter"]',
                "Hunter_API_KEY": "primary-key",
                "HunterIO_API_KEY": "secondary-key",
            },
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                provider_results = {}
                emails = osint_engine.run_emailharvest_passive("example.com", provider_results)

        self.assertEqual(emails, {"alice@example.com"})
        self.assertEqual(len(observed_urls), 2)
        self.assertEqual(provider_results["hunter"]["emails"], ["alice@example.com"])

    def test_hunter_reports_both_configured_keys_rejected(self):
        def fake_safe_get(url, **kwargs):
            if "api.hunter.io/v2/domain-search" in url:
                return FakeResponse(status_code=401, text='{"errors":[{"details":"Unauthorized"}]}')
            return FakeResponse(status_code=404)

        with patch.dict(
            os.environ,
            {
                "OSINT_SELECTED_SOURCES": '["hunter"]',
                "Hunter_API_KEY": "primary-key",
                "HunterIO_API_KEY": "secondary-key",
            },
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                provider_results = {}
                osint_engine.run_emailharvest_passive("example.com", provider_results)

        self.assertIn("Hunter rejected both configured API keys", provider_results["hunter"]["notes"])

    def test_collect_free_provider_subdomains_uses_project_discovery_api(self):
        provider_results = {}

        def fake_safe_get(url, **kwargs):
            if "dns.projectdiscovery.io/dns/example.com/subdomains" in url:
                self.assertEqual(kwargs["headers"]["Authorization"], "pd-test-key")
                return FakeResponse(status_code=200, json_data={"subdomains": ["api", "www"]})
            return FakeResponse(status_code=404)

        with patch.dict(
            os.environ,
            {
                "OSINT_SELECTED_SOURCES": '["projectdiscovery"]',
                "Project_Discovery_API_KEY": "pd-test-key",
            },
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                findings = osint_engine._collect_free_provider_subdomains("example.com", provider_results)

        self.assertEqual(findings["projectdiscovery"], ["api.example.com", "www.example.com"])
        self.assertEqual(provider_results["projectdiscovery"]["subdomains"], ["api.example.com", "www.example.com"])

    def test_collect_free_provider_subdomains_uses_censys_token(self):
        provider_results = {}
        observed_calls = []

        def fake_post(url, **kwargs):
            observed_calls.append((url, kwargs))
            if url == "https://api.platform.censys.io/v3/global/search/query":
                self.assertEqual(kwargs["headers"]["Authorization"], "Bearer censys-pat-test-token")
                self.assertEqual(kwargs["headers"]["X-Organization-ID"], "org-123")
                self.assertEqual(
                    kwargs["json"],
                    {
                        "query": 'names: "example.com"',
                        "per_page": 25,
                    },
                )
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "result": {
                            "hits": [
                                {"names": ["app.example.com", "*.dev.example.com", "example.com"]},
                            ]
                        }
                    },
                )
            return FakeResponse(status_code=404)

        with patch.dict(
            os.environ,
            {
                "OSINT_SELECTED_SOURCES": '["censys"]',
                "Censys_Token": "censys-pat-test-token",
                "Censys_Organization_ID": "org-123",
            },
            clear=False,
        ):
            with patch("osint_engine.requests.post", side_effect=fake_post):
                findings = osint_engine._collect_free_provider_subdomains("example.com", provider_results)

        self.assertEqual(len(observed_calls), 1)
        self.assertEqual(findings["censys"], ["app.example.com", "dev.example.com"])
        self.assertEqual(provider_results["censys"]["subdomains"], ["app.example.com", "dev.example.com"])

    def test_censys_rejects_invalid_pat(self):
        provider_results = {}

        def fake_post(url, **kwargs):
            if url == "https://api.platform.censys.io/v3/global/search/query":
                return FakeResponse(status_code=401, text='{"error":"unauthorized"}')
            return FakeResponse(status_code=404)

        with patch.dict(
            os.environ,
            {
                "OSINT_SELECTED_SOURCES": '["censys"]',
                "Censys_Token": "bad-pat",
            },
            clear=False,
        ):
            with patch("osint_engine.requests.post", side_effect=fake_post):
                findings = osint_engine._collect_free_provider_subdomains("example.com", provider_results)

        self.assertEqual(findings, {})
        self.assertIn("Censys rejected the configured PAT", " ".join(provider_results["censys"]["notes"]))

    def test_censys_requires_organization_id_for_platform_api(self):
        provider_results = {}

        def fake_post(url, **kwargs):
            if url == "https://api.platform.censys.io/v3/global/search/query":
                self.assertNotIn("X-Organization-ID", kwargs["headers"])
                return FakeResponse(
                    status_code=403,
                    text='{"detail":"This endpoint requires an organization ID for API access."}',
                    headers={"content-type": "application/json"},
                )
            return FakeResponse(status_code=404)

        with patch.dict(
            os.environ,
            {
                "OSINT_SELECTED_SOURCES": '["censys"]',
                "Censys_Token": "valid-pat",
            },
            clear=False,
        ):
            with patch("osint_engine.requests.post", side_effect=fake_post):
                findings = osint_engine._collect_free_provider_subdomains("example.com", provider_results)

        self.assertEqual(findings, {})
        self.assertIn(
            "Censys requires Censys_Organization_ID for Platform API access",
            " ".join(provider_results["censys"]["notes"]),
        )

    def test_projectdiscovery_includes_response_body_in_error_note(self):
        provider_results = {}

        def fake_safe_get(url, **kwargs):
            if "dns.projectdiscovery.io/dns/example.com/subdomains" in url:
                return FakeResponse(
                    status_code=500,
                    text='{"message":"internal server error"}',
                    headers={"content-type": "application/json"},
                )
            return FakeResponse(status_code=404)

        with patch.dict(
            os.environ,
            {
                "OSINT_SELECTED_SOURCES": '["projectdiscovery"]',
                "Project_Discovery_API_KEY": "pd-test-key",
            },
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                osint_engine._collect_free_provider_subdomains("example.com", provider_results)

        self.assertIn(
            "HTTP 500 from ProjectDiscovery: internal server error",
            provider_results["projectdiscovery"]["notes"],
        )

    def test_check_breaches_rewords_dehashed_as_hint_only(self):
        provider_results = {}

        with patch(
            "osint_engine.safe_get",
            return_value=FakeResponse(status_code=200, text="<html>results available</html>"),
        ):
            with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["dehashed"]'}, clear=False):
                result = osint_engine.check_breaches("example.com", [], provider_results)

        self.assertEqual(result["dehashed_hint"], "Public DeHashed hint found (full results require authentication)")

    def test_run_recon_returns_provider_results(self):
        fake_provider_results = {
            "rocketreach": {
                "status": "ok",
                "notes": [],
                "emails": ["alice@example.com"],
            }
        }

        with patch("osint_engine.find_website", return_value={"company": "Example", "domain": "example.com", "url": "https://example.com", "found_via": "direct_input"}):
            with patch("osint_engine.dns_enumerate", return_value=osint_engine._empty_dns("example.com")):
                with patch("osint_engine.get_whois", return_value=osint_engine._empty_whois("example.com")):
                    with patch("osint_engine.get_ssl_info", return_value=osint_engine._empty_ssl("example.com")):
                        with patch("osint_engine.get_hosting_info", return_value=osint_engine._empty_hosting("example.com")):
                            with patch("osint_engine.fingerprint_technologies", return_value=osint_engine._empty_tech("https://example.com")):
                                with patch(
                                    "osint_engine.harvest_emails",
                                    return_value={**osint_engine._empty_identities("example.com"), "provider_results": fake_provider_results},
                                ):
                                    with patch("osint_engine.check_breaches", return_value=osint_engine._empty_breaches("example.com")):
                                        result = osint_engine.run_recon("Example")

        self.assertEqual(result["provider_results"]["rocketreach"], fake_provider_results["rocketreach"])

    def test_run_recon_initializes_selected_provider_cards_even_without_findings(self):
        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["duckduckgo", "direct_dns", "whois"]'},
            clear=False,
        ):
            with patch(
                "osint_engine.find_website",
                return_value={"company": "Example", "domain": "example.com", "url": "https://example.com", "found_via": "direct_input"},
            ):
                with patch("osint_engine.dns_enumerate", return_value=osint_engine._empty_dns("example.com")):
                    with patch("osint_engine.get_whois", return_value=osint_engine._empty_whois("example.com")):
                        with patch("osint_engine.get_ssl_info", return_value=osint_engine._empty_ssl("example.com")):
                            with patch("osint_engine.get_hosting_info", return_value=osint_engine._empty_hosting("example.com")):
                                with patch("osint_engine.fingerprint_technologies", return_value=osint_engine._empty_tech("https://example.com")):
                                    with patch("osint_engine.harvest_emails", return_value=osint_engine._empty_identities("example.com")):
                                        with patch("osint_engine.check_breaches", return_value=osint_engine._empty_breaches("example.com")):
                                            result = osint_engine.run_recon("Example")

        self.assertIn("duckduckgo", result["provider_results"])
        self.assertIn("direct_dns", result["provider_results"])
        self.assertIn("whois", result["provider_results"])
        self.assertEqual(result["provider_results"]["duckduckgo"]["status"], "ok")

    def test_run_recon_records_exact_core_provider_details(self):
        dns_result = osint_engine._empty_dns("example.com")
        dns_result["records"] = {"A": ["1.2.3.4"], "TXT": ["v=spf1 include:_spf.example.com ~all"]}
        dns_result["subdomains"] = [{"subdomain": "api.example.com", "type": "A"}]

        whois_result = osint_engine._empty_whois("example.com")
        whois_result["registrar"] = "Example Registrar"

        ssl_result = osint_engine._empty_ssl("example.com")
        ssl_result["valid"] = True
        ssl_result["issuer_cn"] = "Example CA"

        hosting_result = osint_engine._empty_hosting("example.com")
        hosting_result["asn"] = "AS64500"
        hosting_result["open_ports"] = [443, 8443]

        tech_result = osint_engine._empty_tech("https://example.com")
        tech_result["server"] = "cloudflare"

        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["direct_dns", "whois", "ssl_inspection", "ipwhois", "port_scan", "tech_fingerprint"]'},
            clear=False,
        ):
            with patch(
                "osint_engine.find_website",
                return_value={"company": "Example", "domain": "example.com", "url": "https://example.com", "found_via": "direct_input"},
            ):
                with patch("osint_engine.dns_enumerate", return_value=dns_result):
                    with patch("osint_engine.get_whois", return_value=whois_result):
                        with patch("osint_engine.get_ssl_info", return_value=ssl_result):
                            with patch("osint_engine.get_hosting_info", return_value=hosting_result):
                                with patch("osint_engine.fingerprint_technologies", return_value=tech_result):
                                    with patch("osint_engine.harvest_emails", return_value=osint_engine._empty_identities("example.com")):
                                        with patch("osint_engine.check_breaches", return_value=osint_engine._empty_breaches("example.com")):
                                            result = osint_engine.run_recon("Example")

        self.assertIn("1.2.3.4", json.dumps(result["provider_results"]["direct_dns"]["dns_records"]))
        self.assertEqual(result["provider_results"]["direct_dns"]["subdomains"], ["api.example.com"])
        self.assertIn("Example Registrar", json.dumps(result["provider_results"]["whois"]["whois"]))
        self.assertIn("Example CA", json.dumps(result["provider_results"]["ssl_inspection"]["ssl"]))
        self.assertIn("AS64500", json.dumps(result["provider_results"]["ipwhois"]["hosting"]))
        self.assertEqual(result["provider_results"]["port_scan"]["ports"], ["443", "8443"]) 
        self.assertIn("cloudflare", json.dumps(result["provider_results"]["tech_fingerprint"]["tech"]))

    def test_run_recon_skips_unselected_expensive_steps(self):
        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["direct_dns"]'},
            clear=False,
        ):
            with patch(
                "osint_engine.find_website",
                return_value={"company": "Example", "domain": "example.com", "url": "https://example.com", "found_via": "direct_input"},
            ):
                with patch("osint_engine.dns_enumerate", return_value=osint_engine._empty_dns("example.com")):
                    with patch("osint_engine.get_whois", side_effect=AssertionError("whois should be skipped")):
                        with patch("osint_engine.get_ssl_info", side_effect=AssertionError("ssl should be skipped")):
                            with patch("osint_engine.get_hosting_info", side_effect=AssertionError("hosting should be skipped")):
                                with patch("osint_engine.fingerprint_technologies", side_effect=AssertionError("tech should be skipped")):
                                    with patch("osint_engine.harvest_emails", side_effect=AssertionError("identities should be skipped")):
                                        with patch("osint_engine.check_breaches", side_effect=AssertionError("breaches should be skipped")):
                                            result = osint_engine.run_recon("Example")

        self.assertEqual(result["website"]["domain"], "example.com")
        self.assertEqual(result["dns"]["domain"], "example.com")
        self.assertEqual(result["whois"]["domain"], "example.com")
        self.assertEqual(result["ssl"]["domain"], "example.com")
        self.assertEqual(result["hosting"]["domain"], "example.com")
        self.assertEqual(result["technologies"]["url"], "https://example.com")
        self.assertEqual(result["identities"]["domain"], "example.com")
        self.assertEqual(result["breaches"]["domain"], "example.com")

    def test_safe_get_retries_without_tls_verification_on_certificate_failure(self):
        captured = []
        response = FakeResponse(status_code=200, url="https://metrorex.ro/")

        def fake_get(url, **kwargs):
            captured.append(kwargs.copy())
            if len(captured) == 1:
                raise requests.exceptions.SSLError("certificate verify failed")
            return response

        with patch("osint_engine.requests.get", side_effect=fake_get):
            result = osint_engine.safe_get("https://metrorex.ro", timeout=12)

        self.assertIs(result, response)
        self.assertEqual(captured[0]["verify"], True)
        self.assertEqual(captured[1]["verify"], False)

    def test_probe_url_accepts_reachable_403_challenge_pages(self):
        response = FakeResponse(status_code=403, url="https://openai.com/")

        with patch("osint_engine.safe_get", return_value=response):
            final_url, domain = osint_engine._probe_url("https://www.openai.com")

        self.assertEqual(final_url, "https://openai.com/")
        self.assertEqual(domain, "openai.com")

    def test_probe_url_rejects_cross_domain_redirects(self):
        response = FakeResponse(
            status_code=200,
            url="https://docs.google.com/forms/d/e/example/viewform",
        )

        with patch("osint_engine.safe_get", return_value=response):
            final_url, domain = osint_engine._probe_url("https://www.openai.fr")

        self.assertIsNone(final_url)
        self.assertIsNone(domain)

    def test_find_website_prefers_better_ranked_domain_over_faster_response(self):
        def fake_probe(url):
            if url == "https://www.openai.com":
                time.sleep(0.05)
                return ("https://www.openai.com", "openai.com")
            if url == "https://www.openai.nl":
                return ("https://www.openai.nl", "openai.nl")
            return (None, None)

        with patch("osint_engine._probe_url", side_effect=fake_probe):
            result = osint_engine.find_website("OpenAI")

        self.assertEqual(result["domain"], "openai.com")
        self.assertEqual(result["url"], "https://www.openai.com")

    def test_find_website_uses_brave_search_when_selected_and_configured(self):
        def fake_safe_get(url, **kwargs):
            if "api.search.brave.com" in url:
                return FakeResponse(
                    status_code=200,
                    json_data={
                        "web": {
                            "results": [
                                {"url": "https://www.example.com/about", "title": "Example"},
                            ]
                        }
                    },
                )
            return FakeResponse(status_code=404)

        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["brave"]', "BRAVE_SEARCH_API_KEY": "brave-test-key"},
            clear=False,
        ):
            with patch("osint_engine._probe_url", return_value=(None, None)):
                with patch("osint_engine._is_valid_domain", return_value=True):
                    with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                        result = osint_engine.find_website("Example")

        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["found_via"], "brave_search")

    def test_find_website_uses_google_search_when_selected(self):
        def fake_safe_get(url, **kwargs):
            if "google.com/search" in url:
                return FakeResponse(
                    status_code=200,
                    text="""
                        <html>
                          <body>
                            <div class="g">
                              <a href="https://www.example.com/about">Example official website</a>
                              <span>Official example.com company website.</span>
                            </div>
                          </body>
                        </html>
                    """,
                )
            return FakeResponse(status_code=404)

        with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["google"]'}, clear=False):
            with patch("osint_engine._probe_url", return_value=(None, None)):
                with patch("osint_engine._is_valid_domain", return_value=True):
                    with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                        result = osint_engine.find_website("Example")

        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["found_via"], "google_search")

    def test_run_recon_attributes_search_provider_used_for_website_discovery(self):
        website_info = {
            "company": "Example",
            "domain": "example.com",
            "url": "https://example.com",
            "found_via": "bing_search",
        }

        with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["bing"]'}, clear=False):
            with patch("osint_engine.find_website", return_value=website_info):
                with patch("osint_engine.dns_enumerate", return_value=osint_engine._empty_dns("example.com")):
                    with patch("osint_engine.get_whois", return_value=osint_engine._empty_whois("example.com")):
                        with patch("osint_engine.get_ssl_info", return_value=osint_engine._empty_ssl("example.com")):
                            with patch("osint_engine.get_hosting_info", return_value=osint_engine._empty_hosting("example.com")):
                                with patch("osint_engine.fingerprint_technologies", return_value=osint_engine._empty_tech("https://example.com")):
                                    with patch("osint_engine.harvest_emails", return_value=osint_engine._empty_identities("example.com")):
                                        with patch("osint_engine.check_breaches", return_value=osint_engine._empty_breaches("example.com")):
                                            result = osint_engine.run_recon("Example")

        self.assertIn("bing", result["provider_results"])
        self.assertIn("example.com", json.dumps(result["provider_results"]["bing"]))

    def test_harvest_emails_attributes_wikidata_social_profiles(self):
        fake_profiles = {
            "LinkedIn": {"url": "https://linkedin.com/company/example", "status": "found", "source": "wikidata"},
        }

        with patch("osint_engine.run_theharvester", return_value=set()):
            with patch("osint_engine.run_recon_ng", return_value=set()):
                with patch("osint_engine.run_rocketreach", return_value=set()):
                    with patch("osint_engine.run_emailharvest_passive", return_value=set()):
                        with patch("osint_engine.safe_get", return_value=None):
                            with patch("osint_engine.discover_social_profiles", return_value=fake_profiles):
                                result = osint_engine.harvest_emails("example.com", "Example")

        self.assertEqual(
            result["provider_results"]["wikidata"]["social_profiles"],
            [{"LinkedIn": fake_profiles["LinkedIn"]}],
        )

    def test_harvest_emails_attributes_slug_social_profiles_to_social_probe(self):
        fake_profiles = {
            "GitHub": {"url": "https://github.com/example", "status": "found", "source": "slug:example"},
        }

        with patch("osint_engine.run_theharvester", return_value=set()):
            with patch("osint_engine.run_recon_ng", return_value=set()):
                with patch("osint_engine.run_rocketreach", return_value=set()):
                    with patch("osint_engine.run_emailharvest_passive", return_value=set()):
                        with patch("osint_engine.safe_get", return_value=None):
                            with patch("osint_engine.discover_social_profiles", return_value=fake_profiles):
                                result = osint_engine.harvest_emails("example.com", "Example")

        self.assertEqual(
            result["provider_results"]["social_probe"]["social_profiles"],
            [{"GitHub": fake_profiles["GitHub"]}],
        )

    def test_harvest_emails_includes_sherlock_impersonation_candidates(self):
        fake_profiles = {
            "LinkedIn": {"url": "https://www.linkedin.com/company/example", "status": "found", "source": "sherlock"},
        }
        fake_impersonation = [
            {
                "platform": "GitHub",
                "username": "example_support",
                "url": "https://github.com/example_support",
                "matched_candidate": "example_support",
                "reason": "support suffix variation",
                "source": "sherlock",
            }
        ]

        with patch("osint_engine.run_theharvester", return_value=set()):
            with patch("osint_engine.run_recon_ng", return_value=set()):
                with patch("osint_engine.run_rocketreach", return_value=set()):
                    with patch("osint_engine.run_emailharvest_passive", return_value=set()):
                        with patch("osint_engine.safe_get", return_value=None):
                            with patch("osint_engine.discover_social_profiles", return_value=fake_profiles):
                                with patch(
                                    "osint_engine.run_sherlock",
                                    return_value={
                                        "profiles": fake_profiles,
                                        "impersonation_candidates": fake_impersonation,
                                    },
                                ):
                                    with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["sherlock"]'}, clear=False):
                                        result = osint_engine.harvest_emails("example.com", "Example")

        self.assertEqual(result["impersonation_candidates"], fake_impersonation)
        self.assertEqual(
            result["provider_results"]["sherlock"]["social_profiles"],
            [{"LinkedIn": fake_profiles["LinkedIn"]}],
        )
        self.assertEqual(
            result["provider_results"]["sherlock"]["impersonation_candidates"],
            fake_impersonation,
        )

    def test_sherlock_handle_candidates_are_bounded(self):
        candidates = osint_engine.sherlock_handle_candidates("openai.com", "OpenAI")

        self.assertIn("openai", candidates)
        self.assertLessEqual(len(candidates), 3)

    def test_run_sherlock_keeps_partial_results_on_timeout(self):
        provider_results = {}

        first = osint_engine.subprocess.CompletedProcess(
            args=["sherlock"],
            returncode=0,
            stdout="[+] GitHub: https://github.com/example\n",
            stderr="",
        )

        with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["sherlock"]'}, clear=False):
            with patch("osint_engine._which", return_value="sherlock"):
                with patch(
                    "osint_engine.subprocess.run",
                    side_effect=[first, osint_engine.subprocess.TimeoutExpired(cmd=["sherlock"], timeout=90)],
                ):
                    result = osint_engine.run_sherlock("example.com", "Example", provider_results)

        self.assertEqual(
            result["profiles"]["GitHub"],
            {"url": "https://github.com/example", "status": "found", "source": "sherlock"},
        )
        self.assertNotEqual(provider_results["sherlock"]["status"], "error")
        self.assertIn(
            "Timed out after partial scan; returning collected Sherlock hits",
            provider_results["sherlock"]["notes"],
        )

    def test_run_sherlock_filters_profiles_that_fail_profile_verification(self):
        provider_results = {}
        completed = osint_engine.subprocess.CompletedProcess(
            args=["sherlock"],
            returncode=0,
            stdout=(
                "[+] GitHub: https://github.com/example\n"
                "[+] YouTube: https://www.youtube.com/@example\n"
            ),
            stderr="",
        )

        with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["sherlock"]'}, clear=False):
            with patch("osint_engine._which", return_value="sherlock"):
                with patch("osint_engine.subprocess.run", return_value=completed):
                    with patch(
                        "osint_engine._verify_profile",
                        side_effect=[
                            {"url": "https://github.com/example", "status": "found"},
                            {"url": "https://www.youtube.com/@example", "status": "not_found"},
                        ],
                    ):
                        result = osint_engine.run_sherlock("example.com", "Example", provider_results)

        self.assertEqual(
            result["profiles"],
            {"GitHub": {"url": "https://github.com/example", "status": "found", "source": "sherlock"}},
        )
        self.assertEqual(
            provider_results["sherlock"]["social_profiles"],
            [{"GitHub": {"url": "https://github.com/example", "status": "found", "source": "sherlock"}}],
        )

    def test_run_spiderfoot_uses_configured_timeout_and_reports_it(self):
        provider_results = {}

        with patch.dict(
            os.environ,
            {
                "OSINT_SELECTED_SOURCES": '["spiderfoot"]',
                "SPIDERFOOT_TIMEOUT_MS": "1000",
            },
            clear=False,
        ):
            with patch("osint_engine._which", return_value="sf.py"):
                with patch(
                    "osint_engine._run_command_with_timeout",
                    side_effect=osint_engine.subprocess.TimeoutExpired(cmd=["sf.py"], timeout=1),
                ) as mocked_run:
                    result = osint_engine.run_spiderfoot("example.com", "Example", provider_results)

        self.assertEqual(result["emails"], set())
        self.assertEqual(result["subdomains"], set())
        self.assertEqual(result["social_profiles"], {})
        self.assertEqual(mocked_run.call_args.kwargs["timeout"], 1)
        self.assertIn("Timed out after 1s", provider_results["spiderfoot"]["notes"])

    def test_run_spiderfoot_uses_120_second_default_timeout(self):
        provider_results = {}

        with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["spiderfoot"]'}, clear=False):
            with patch("osint_engine._which", return_value="sf.py"):
                with patch(
                    "osint_engine._run_command_with_timeout",
                    side_effect=osint_engine.subprocess.TimeoutExpired(cmd=["sf.py"], timeout=120),
                ) as mocked_run:
                    osint_engine.run_spiderfoot("example.com", "Example", provider_results)

        self.assertEqual(mocked_run.call_args.kwargs["timeout"], 120)
        self.assertIn("Timed out after 120s", provider_results["spiderfoot"]["notes"])

    def test_run_spiderfoot_skips_when_not_installed(self):
        provider_results = {}

        with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["spiderfoot"]'}, clear=False):
            with patch("osint_engine._which", return_value=None):
                with patch("osint_engine._repo_tool_path", return_value=None):
                    result = osint_engine.run_spiderfoot("example.com", "Example", provider_results)

        self.assertEqual(result["emails"], set())
        self.assertEqual(result["subdomains"], set())
        self.assertEqual(result["social_profiles"], {})
        self.assertEqual(provider_results["spiderfoot"]["status"], "skipped")
        self.assertIn("SpiderFoot not found on PATH", provider_results["spiderfoot"]["notes"])

    def test_run_spiderfoot_parses_relevant_findings(self):
        provider_results = {}
        payload = json.dumps(
            [
                {"type": "EMAILADDR", "data": "security@example.com"},
                {"type": "INTERNET_NAME", "data": "api.example.com"},
                {"type": "SOCIAL_MEDIA", "data": "https://github.com/example"},
                {"type": "LINKED_URL_EXTERNAL", "data": "https://news.example.com/post"},
            ]
        )
        completed = osint_engine.subprocess.CompletedProcess(
            args=["sf.py"],
            returncode=0,
            stdout=payload,
            stderr="",
        )

        with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["spiderfoot"]'}, clear=False):
            with patch("osint_engine._which", return_value="sf.py"):
                with patch("osint_engine._run_command_with_timeout", return_value=completed):
                    result = osint_engine.run_spiderfoot("example.com", "Example", provider_results)

        self.assertEqual(result["emails"], {"security@example.com"})
        self.assertEqual(result["subdomains"], {"api.example.com"})
        self.assertIn("GitHub", result["social_profiles"])
        self.assertEqual(result["social_profiles"]["GitHub"]["source"], "spiderfoot")
        self.assertEqual(len(result["mentions"]), 1)
        self.assertEqual(provider_results["spiderfoot"]["emails"], ["security@example.com"])
        self.assertEqual(provider_results["spiderfoot"]["subdomains"], ["api.example.com"])

    def test_run_emailharvest_passive_records_auth_and_payload_notes(self):
        provider_results = {}

        def fake_safe_get(url, **kwargs):
            if "api.hunter.io" in url:
                return FakeResponse(status_code=401, text='{"errors":[{"details":"bad key"}]}')
            if "phonebook.cz" in url:
                return FakeResponse(status_code=200, text="<html>phonebook</html>")
            if "api.github.com/search/code" in url:
                return FakeResponse(status_code=401, text='{"message":"Requires authentication"}')
            raise AssertionError(f"unexpected url {url}")

        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["hunter","phonebook_cz","github_code"]'},
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                osint_engine.run_emailharvest_passive("example.com", provider_results)

        self.assertIn("401", " ".join(provider_results["hunter"]["notes"]))
        self.assertIn("HTML", " ".join(provider_results["phonebook_cz"]["notes"]))
        self.assertIn("authentication", " ".join(provider_results["github_code"]["notes"]).lower())

    def test_dns_enumerate_records_provider_notes_for_blocked_free_sources(self):
        provider_results = {}

        def fake_safe_get(url, **kwargs):
            if "tls.bufferover.run" in url:
                return FakeResponse(status_code=403, text='{"message":"Forbidden"}')
            if "api.threatminer.org" in url:
                return FakeResponse(status_code=500, text="")
            return FakeResponse(status_code=404, text="")

        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["bufferoverun","threatminer"]'},
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                osint_engine.dns_enumerate("example.com", provider_results)

        self.assertIn("403", " ".join(provider_results["bufferoverun"]["notes"]))
        self.assertIn("500", " ".join(provider_results["threatminer"]["notes"]))

    def test_harvest_emails_records_hibp_auth_note(self):
        def fake_safe_get(url, **kwargs):
            if "haveibeenpwned.com/api/v3/subscribeddomains" in url:
                return FakeResponse(status_code=401, text='{"message":"Access denied due to missing hibp-api-key."}')
            return None

        with patch("osint_engine.run_theharvester", return_value=set()):
            with patch("osint_engine.run_recon_ng", return_value=set()):
                with patch("osint_engine.run_rocketreach", return_value=set()):
                    with patch("osint_engine.run_emailharvest_passive", return_value=set()):
                        with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                            with patch("osint_engine.discover_social_profiles", return_value={}):
                                with patch.dict(
                                    os.environ,
                                    {"OSINT_SELECTED_SOURCES": '["hibp"]', "HaveIBeenPwned_API_KEY": "hibp-test-key"},
                                    clear=False,
                                ):
                                    result = osint_engine.harvest_emails("example.com", "Example")

        self.assertIn("HIBP rejected the configured API key", " ".join(result["provider_results"]["hibp"]["notes"]))

    def test_harvest_emails_records_empty_notes_for_recon_ng_and_rocketreach(self):
        with patch("osint_engine.run_theharvester", return_value=set()):
            with patch("osint_engine.run_recon_ng", return_value=set()):
                with patch("osint_engine.run_rocketreach", return_value=set()):
                    with patch("osint_engine.run_emailharvest_passive", return_value=set()):
                        with patch("osint_engine.safe_get", return_value=None):
                            with patch("osint_engine.discover_social_profiles", return_value={}):
                                with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["recon_ng","rocketreach"]'}, clear=False):
                                    result = osint_engine.harvest_emails("example.com", "Example")

        self.assertEqual(result["provider_results"]["recon_ng"]["notes"], ["No matching emails found"])
        self.assertEqual(result["provider_results"]["rocketreach"]["notes"], ["No matching emails found"])

    def test_harvest_emails_skips_extra_social_and_crawl_work_for_spiderfoot_only(self):
        spiderfoot_findings = {
            "emails": {"security@example.com"},
            "subdomains": set(),
            "social_profiles": {},
            "mentions": [],
            "hosting": [],
        }

        with patch("osint_engine.run_theharvester", return_value=set()):
            with patch("osint_engine.run_recon_ng", return_value=set()):
                with patch("osint_engine.run_rocketreach", return_value=set()):
                    with patch("osint_engine.run_emailharvest_passive", return_value=set()):
                        with patch("osint_engine.run_spiderfoot", return_value=spiderfoot_findings):
                            with patch("osint_engine.safe_get", side_effect=AssertionError("homepage crawl should be skipped")):
                                with patch(
                                    "osint_engine.discover_social_profiles",
                                    side_effect=AssertionError("social discovery should be skipped"),
                                ):
                                    with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["spiderfoot"]'}, clear=False):
                                        result = osint_engine.harvest_emails("example.com", "Example")

        self.assertEqual(result["emails"], ["security@example.com"])
        self.assertEqual(result["social_profiles"], {})
        self.assertEqual(result["impersonation_candidates"], [])

    def test_check_breaches_records_dehashed_empty_note(self):
        provider_results = {}

        with patch("osint_engine.safe_get", return_value=FakeResponse(status_code=200, text="<html>no results</html>")):
            with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["dehashed"]'}, clear=False):
                osint_engine.check_breaches("example.com", [], provider_results)

        self.assertIn("No public DeHashed hint found", " ".join(provider_results["dehashed"]["notes"]))

    def test_run_recon_returns_stage_timings(self):
        with patch("osint_engine.find_website", return_value={"company": "Example", "domain": "example.com", "url": "https://example.com", "found_via": "direct_fallback"}):
            with patch("osint_engine.dns_enumerate", return_value=osint_engine._empty_dns("example.com")):
                with patch("osint_engine.get_whois", return_value=osint_engine._empty_whois("example.com")):
                    with patch("osint_engine.get_ssl_info", return_value=osint_engine._empty_ssl("example.com")):
                        with patch("osint_engine.get_hosting_info", return_value=osint_engine._empty_hosting("example.com")):
                            with patch("osint_engine.fingerprint_technologies", return_value=osint_engine._empty_tech("https://example.com")):
                                with patch(
                                    "osint_engine.harvest_emails",
                                    return_value={
                                        "domain": "example.com",
                                        "emails": [],
                                        "email_format": None,
                                        "github_repos": [],
                                        "linkedin_presence": None,
                                        "social_profiles": {},
                                        "impersonation_candidates": [],
                                        "provider_results": {},
                                    },
                                ):
                                    with patch("osint_engine.check_breaches", return_value=osint_engine._empty_breaches("example.com")):
                                        report = osint_engine.run_recon("Example")

        self.assertIn("timings", report)
        self.assertIn("total_ms", report["timings"])
        self.assertIn("stages", report["timings"])
        self.assertIn("website", report["timings"]["stages"])
        self.assertIn("dns", report["timings"]["stages"])
        self.assertIn("identities", report["timings"]["stages"])
        self.assertGreaterEqual(report["timings"]["total_ms"], 0)

    def test_dns_enumerate_collects_first_class_free_provider_subdomains(self):
        provider_results = {}

        def fake_safe_get(url, **kwargs):
            if "tls.bufferover.run" in url:
                return FakeResponse(
                    status_code=200,
                    json_data={"FDNS_A": ["1.1.1.1,api.example.com"], "Results": ["mx.example.com"]},
                )
            if "rapiddns.io" in url:
                return FakeResponse(status_code=200, text="vpn.example.com dev.example.com")
            if "api.hackertarget.com" in url:
                return FakeResponse(status_code=200, text="portal.example.com,1.2.3.4")
            if "api.threatminer.org" in url:
                return FakeResponse(status_code=200, json_data={"status_code": "200", "results": ["mail.example.com"]})
            if "urlscan.io" in url:
                return FakeResponse(
                    status_code=200,
                    json_data={"results": [{"page": {"domain": "cdn.example.com"}}]},
                )
            raise AssertionError(f"unexpected url {url}")

        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["bufferoverun", "rapiddns", "hackertarget", "threatminer", "urlscan"]'},
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                result = osint_engine.dns_enumerate("example.com", provider_results)

        subdomains = {entry["subdomain"] for entry in result["subdomains"]}
        self.assertIn("api.example.com", subdomains)
        self.assertIn("vpn.example.com", subdomains)
        self.assertIn("portal.example.com", subdomains)
        self.assertIn("mail.example.com", subdomains)
        self.assertIn("cdn.example.com", subdomains)
        self.assertEqual(provider_results["bufferoverun"]["subdomains"], ["api.example.com", "mx.example.com"])
        self.assertEqual(provider_results["hackertarget"]["subdomains"], ["portal.example.com"])

    def test_dns_enumerate_collects_remaining_public_subdomain_providers(self):
        provider_results = {}

        def fake_safe_get(url, **kwargs):
            if "api.subdomain.center" in url:
                return FakeResponse(status_code=200, json_data=["api.example.com", "www.example.com"])
            if "subdomainfinder.c99.nl" in url:
                return FakeResponse(status_code=200, text="dev.example.com test.example.com")
            if "ip.thc.org" in url:
                return FakeResponse(status_code=200, text="mail.example.com\ncdn.example.com")
            raise AssertionError(f"unexpected url {url}")

        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["subdomaincenter", "subdomainfinderc99", "thc"]'},
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                result = osint_engine.dns_enumerate("example.com", provider_results)

        subdomains = {entry["subdomain"] for entry in result["subdomains"]}
        self.assertIn("api.example.com", subdomains)
        self.assertIn("dev.example.com", subdomains)
        self.assertIn("mail.example.com", subdomains)
        self.assertEqual(provider_results["subdomaincenter"]["subdomains"], ["api.example.com", "www.example.com"])
        self.assertEqual(provider_results["subdomainfinderc99"]["subdomains"], ["dev.example.com", "test.example.com"])
        self.assertEqual(provider_results["thc"]["subdomains"], ["cdn.example.com", "mail.example.com"])

    def test_run_emailharvest_passive_collects_google_evidence(self):
        provider_results = {}

        def fake_safe_get(url, **kwargs):
            if "google.com/search" in url:
                return FakeResponse(
                    status_code=200,
                    text="""
                        <html>
                          <body>
                            <a href="https://www.google.com/search?sca_esv=test">Ignored shell</a>
                            <div class="g">
                              <a href="https://www.reddit.com/r/example/comments/123">Metrorex forum mention</a>
                              <span>Employees discuss example.com and list info@example.com for contact.</span>
                            </div>
                            <div class="g">
                              <a href="https://careers.example.com/jobs/platform-engineer">Platform Engineer</a>
                              <span>Join example.com careers. Contact jobs@example.com.</span>
                            </div>
                            <div class="g">
                              <a href="https://support.google.com/websearch/answer/2466433">Google support</a>
                              <span>Should not appear in provider results.</span>
                            </div>
                          </body>
                        </html>
                    """,
                )
            raise AssertionError(f"unexpected url {url}")

        with patch.dict(
            os.environ,
            {"OSINT_SELECTED_SOURCES": '["google"]'},
            clear=False,
        ):
            with patch("osint_engine.safe_get", side_effect=fake_safe_get):
                emails = osint_engine.run_emailharvest_passive("example.com", provider_results)

        self.assertEqual(emails, {"info@example.com", "jobs@example.com"})
        self.assertEqual(provider_results["google"]["emails"], ["info@example.com", "jobs@example.com"])
        self.assertEqual(len(provider_results["google"]["mentions"]), 2)
        self.assertEqual(provider_results["google"]["mentions"][0]["category"], "forum")
        self.assertEqual(provider_results["google"]["mentions"][1]["category"], "jobs")
        self.assertNotIn(
            "support.google.com",
            " ".join(mention.get("url", "") for mention in provider_results["google"]["mentions"]),
        )

    def test_run_emailharvest_passive_records_windvane_diagnostic_note(self):
        provider_results = {}

        with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["windvane"]'}, clear=False):
            with patch("osint_engine.safe_get", return_value=FakeResponse(status_code=403, text="forbidden")):
                osint_engine.run_emailharvest_passive("example.com", provider_results)

        self.assertIn("403", " ".join(provider_results["windvane"]["notes"]))

    def test_fingerprint_technologies_uses_headers_from_403_responses(self):
        response = FakeResponse(
            status_code=403,
            url="https://openai.com/",
            text="<html>challenge</html>",
            headers={
                "server": "cloudflare",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "SAMEORIGIN",
            },
        )

        with patch("osint_engine.safe_get", return_value=response):
            result = osint_engine.fingerprint_technologies("https://openai.com")

        self.assertEqual(result["server"], "cloudflare")
        self.assertTrue(result["security_headers"]["CSP"]["present"]) 
        self.assertTrue(result["security_headers"]["X-Frame-Options"]["present"]) 

    def test_safe_get_allows_timeout_override(self):
        captured = {}

        def fake_get(url, **kwargs):
            captured["url"] = url
            captured["kwargs"] = kwargs
            return FakeResponse()

        with patch("osint_engine.requests.get", side_effect=fake_get):
            response = osint_engine.safe_get("https://example.com", timeout=17)

        self.assertIsNotNone(response)
        self.assertEqual(captured["url"], "https://example.com")
        self.assertEqual(captured["kwargs"]["timeout"], 17)
        self.assertTrue(captured["kwargs"]["allow_redirects"]) 

    def test_dns_enumerate_falls_back_to_public_resolvers_when_default_times_out(self):
        default_failures = {
            ("openai.com", "A"),
            ("openai.com", "AAAA"),
            ("openai.com", "CNAME"),
            ("openai.com", "MX"),
            ("openai.com", "NS"),
            ("openai.com", "TXT"),
            ("openai.com", "SOA"),
            ("openai.com", "CAA"),
            ("_dmarc.openai.com", "TXT"),
        }
        default_resolver = FakeResolver(failures=default_failures)
        fallback_resolver = FakeResolver(
            answers={
                ("openai.com", "A"): [FakeAnswer("104.18.33.45"), FakeAnswer("172.64.154.211")],
                ("openai.com", "NS"): [FakeAnswer("ns1.example.net."), FakeAnswer("ns2.example.net.")],
                ("openai.com", "MX"): [FakeAnswer("10 mx1.openai.com.", preference=10, exchange="mx1.openai.com.")],
                ("openai.com", "TXT"): [FakeAnswer('"v=spf1 include:_spf.google.com ~all"')],
                ("_dmarc.openai.com", "TXT"): [FakeAnswer('"v=DMARC1; p=reject;"')],
            }
        )

        resolver_calls = []

        def fake_resolver_factory(*args, **kwargs):
            resolver_calls.append(kwargs)
            if kwargs.get("configure") is False:
                return fallback_resolver
            return default_resolver

        with patch("osint_engine.dns.resolver.Resolver", side_effect=fake_resolver_factory):
            with patch("osint_engine.safe_get", return_value=None):
                results = osint_engine.dns_enumerate("openai.com")

        self.assertEqual(results["records"]["A"], ["104.18.33.45", "172.64.154.211"]) 
        self.assertEqual(results["nameservers"], ["ns1.example.net.", "ns2.example.net."])
        self.assertEqual(results["spf"], '"v=spf1 include:_spf.google.com ~all"')
        self.assertEqual(results["dmarc"], '"v=DMARC1; p=reject;"')
        self.assertIn({"priority": 10, "host": "mx1.openai.com."}, results["mx_records"]) 
        self.assertIn({"configure": False}, resolver_calls)

    # --- New tests for recent helper behaviors ---
    def test_initialize_selected_provider_results_populates_selected_providers(self):
        provider_results = {}
        with patch.dict(os.environ, {"OSINT_SELECTED_SOURCES": '["duckduckgo", "censys"]'}, clear=False):
            osint_engine.initialize_selected_provider_results(provider_results)

        self.assertIn("duckduckgo", provider_results)
        self.assertIn("censys", provider_results)
        self.assertEqual(provider_results["duckduckgo"]["status"], "ok")
        self.assertEqual(provider_results["censys"]["status"], "ok")

    def test_rocketreach_company_variants_normalizes_and_deduplicates(self):
        variants = osint_engine.rocketreach_company_variants("example.com", "Example-Name.Inc")
        # Should include cleaned company forms and the domain-derived forms
        self.assertIn("Example-Name.Inc", variants)
        self.assertIn("example.com", variants)
        self.assertIn("example", variants)
        # Ensure there are no duplicate entries
        self.assertEqual(len(variants), len(set(variants)))

    def test_response_detail_prefers_message_field_when_json_body_in_text(self):
        # Simulate a response where response.json() returns {} but response.text contains JSON with message
        resp = FakeResponse(status_code=500, text='{"message":"internal error occurred"}', json_data={})
        detail = osint_engine._response_detail(resp)
        self.assertEqual(detail, "internal error occurred")

    def test_extract_http_urls_removes_trailing_punctuation_and_dedups(self):
        text = "Links: https://example.com/contact, https://example.com/contact. https://other.test/path)"
        urls = osint_engine._extract_http_urls(text)
        self.assertIn("https://example.com/contact", urls)
        self.assertIn("https://other.test/path", urls)
        # contact should appear only once
        self.assertEqual(urls.count("https://example.com/contact"), 1)

    def test_extract_matching_subdomains_handles_wildcards_and_excludes_root(self):
        text = "Found: api.example.com, *.dev.example.com, example.com, sub.EXAMPLE.COM"
        matches = osint_engine._extract_matching_subdomains(text, "example.com")
        # Expect lowercased, wildcard stripped, and root domain excluded
        self.assertEqual(sorted(matches), ["api.example.com", "dev.example.com", "sub.example.com"])


if __name__ == "__main__":
    unittest.main()
