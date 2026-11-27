import io
import ipaddress
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from scripts import update_rules as updater

FIXTURES = Path(__file__).parent / "fixtures"


def source(behavior, flag=False):
    return updater.Source("sample", behavior, "https://example.invalid/fixture", flag)


def matches(rule, destination):
    kind, value, *_ = rule.split(",")
    if kind == "DOMAIN":
        return destination == value
    if kind == "DOMAIN-SUFFIX":
        return destination == value or destination.endswith(f".{value}")
    if kind in ("IP-CIDR", "IP-CIDR6"):
        try:
            return ipaddress.ip_address(destination) in ipaddress.ip_network(value)
        except ValueError:
            return False
    return False


class RuleTests(unittest.TestCase):
    def test_domain_semantics(self):
        exact, suffix, _ = updater.parse_payload((FIXTURES / "domain.yaml").read_text())
        self.assertEqual(updater.convert_rule(exact, source("domain")), "DOMAIN,router.asus.com")
        self.assertEqual(updater.convert_rule(suffix, source("domain")), "DOMAIN-SUFFIX,qq.com")
        for pattern in ("*.example.com", ".example.com", "a.*.example.com", "a..com"):
            with self.subTest(pattern=pattern), self.assertRaisesRegex(ValueError, "unsupported domain"):
                updater.convert_rule(pattern, source("domain"))

    def test_cidr_ipv4_ipv6_and_resolve_flags(self):
        ipv4, ipv6 = updater.parse_payload((FIXTURES / "ipcidr.yaml").read_text())
        self.assertEqual(updater.convert_rule(ipv4, source("ipcidr", True)), "IP-CIDR,192.168.0.0/16,no-resolve")
        self.assertEqual(updater.convert_rule(ipv6, source("ipcidr")), "IP-CIDR6,fe80::/10")
        for item in ("192.168.1.1/16", "192.168.1.1", "fe80::/140"):
            with self.subTest(item=item), self.assertRaises(ValueError):
                updater.convert_rule(item, source("ipcidr"))

    def test_classical_process_and_forbidden_targets(self):
        self.assertEqual(updater.convert_rule("PROCESS-NAME,frpc.exe", source("classical")), "PROCESS-NAME,frpc.exe")
        for item in ("DOMAIN,example.com,DIRECT", "IP-CIDR,1.0.1.0/24,PROXY", "MATCH,DIRECT"):
            with self.subTest(item=item), self.assertRaises(ValueError):
                updater.convert_rule(item, source("classical"))

    def test_payload_rejects_empty_html_and_nonstrings(self):
        for text in ("", "<html>HTTP error</html>", "payload: []", "payload: wrong", "payload: [1]", "payload: ['']"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                updater.parse_payload(text)

    def test_network_retry_and_permanent_failure(self):
        with patch.object(updater, "urlopen", side_effect=URLError("timeout")) as fetch, patch.object(updater.time, "sleep"):
            with self.assertRaises(URLError):
                updater.download(source("domain").url)
            self.assertEqual(fetch.call_count, 3)
        refused = HTTPError(source("domain").url, 404, "missing", {}, None)
        with patch.object(updater, "urlopen", side_effect=refused) as fetch:
            with self.assertRaises(HTTPError):
                updater.download(source("domain").url)
            fetch.assert_called_once()

    def test_stable_category_deduplication(self):
        items = {category: [source("domain"), source("domain")] for category in updater.CATEGORIES}
        data = (FIXTURES / "domain.yaml").read_text()
        reordered = "payload: ['+.qq.com', router.asus.com]"
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            directory = Path(tmp)
            with patch.object(updater, "download", return_value=data):
                updater.publish(updater.collect_rules(items), directory)
            snapshot = {p.name: p.read_bytes() for p in directory.iterdir()}
            with patch.object(updater, "download", return_value=reordered):
                updater.publish(updater.collect_rules(items), directory)
            self.assertEqual(snapshot, {p.name: p.read_bytes() for p in directory.iterdir()})
            self.assertEqual(len(updater.read_output(directory / "direct.yaml")), 2)
            self.assertEqual(snapshot["all.yaml"], snapshot["direct.yaml"])

    def test_combined_provider_includes_every_category_once(self):
        outputs = {
            "direct": ["DOMAIN,a.test", "DOMAIN,b.test"],
            "proxy": ["DOMAIN,b.test", "IP-CIDR,91.108.4.0/22"],
            "reject": ["DOMAIN,c.test"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            updater.publish(outputs, directory)
            self.assertEqual(
                updater.read_output(directory / "all.yaml"),
                ["DOMAIN,a.test", "DOMAIN,b.test", "DOMAIN,c.test", "IP-CIDR,91.108.4.0/22"],
            )

    def test_custom_direct_template_and_merge(self):
        template = FIXTURES / "custom-direct.yaml"
        self.assertEqual(updater.read_custom_direct(template), set())
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            custom = Path(tmp) / "direct.yaml"
            output = Path(tmp) / "rules"
            text = template.read_text(encoding="utf-8").replace("  # - ", "  - ")
            custom.write_text(text, encoding="utf-8")
            custom_rules = updater.read_custom_direct(custom)
            self.assertEqual(len(custom_rules), 6)
            self.assertIn("DOMAIN-KEYWORD,example-brand", custom_rules)
            self.assertIn("DOMAIN-WILDCARD,api-*.example.net", custom_rules)
            duplicate = "DOMAIN,portal.example.com"
            upstream = {"direct": [duplicate], "proxy": ["DOMAIN,proxy.test"], "reject": ["DOMAIN,ads.test"]}
            argv = ["update_rules.py", "--output-dir", str(output), "--custom-direct", str(custom)]
            with patch.object(updater, "collect_rules", return_value=upstream), patch.object(updater.sys, "argv", argv):
                self.assertEqual(updater.main(), 0)
            self.assertEqual(updater.read_output(output / "direct.yaml"), sorted(custom_rules))
            self.assertEqual(updater.read_output(output / "proxy.yaml"), upstream["proxy"])
            self.assertEqual(updater.read_output(output / "reject.yaml"), upstream["reject"])
            self.assertTrue(custom_rules.issubset(updater.read_output(output / "all.yaml")))

            custom.write_text("payload:\n  - DOMAIN,example.com,DIRECT\n", encoding="utf-8")
            with patch.object(updater, "collect_rules") as collect, patch.object(updater.sys, "argv", argv):
                with redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(updater.main(), 1)
                collect.assert_not_called()
            self.assertIn(f"{custom}: payload entry 1", errors.getvalue())
            self.assertEqual(updater.read_output(output / "direct.yaml"), sorted(custom_rules))

    def test_failed_sources_leave_all_previous_outputs_untouched(self):
        valid = "payload: [example.com]"
        failures = (URLError("offline"), "payload: []", "payload: ['*.example.com']")
        for failure in failures:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp)
                for category in updater.PROVIDERS:
                    (output / f"{category}.yaml").write_text(f"previous {category}")
                argv = ["update_rules.py", "--output-dir", tmp]
                responses = [valid] * 4 + ["payload: [192.168.0.0/16]"] * 2 + [valid] * 2 + ["payload: [91.108.4.0/22]", failure]
                with patch.object(updater.sys, "argv", argv), patch.object(updater, "download", side_effect=responses):
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        self.assertEqual(updater.main(), 1)
                for category in updater.PROVIDERS:
                    self.assertEqual((output / f"{category}.yaml").read_text(), f"previous {category}")

    def test_validate_before_replace(self):
        valid = ["DOMAIN,a.test"]
        outputs = {"direct": valid, "proxy": valid, "reject": []}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            previous = directory / "direct.yaml"
            previous.write_text("previous")
            with self.assertRaises(ValueError):
                updater.publish(outputs, directory)
            self.assertEqual(previous.read_text(), "previous")
            self.assertEqual(list(directory.iterdir()), [previous])

    def test_routing_examples(self):
        config = updater.load_yaml((updater.ROOT / "clash-example.yaml").read_text())
        providers = {
            "direct": ["DOMAIN-SUFFIX,qq.com", "DOMAIN-SUFFIX,conflict.test", "DOMAIN-SUFFIX,ads.test"],
            "proxy": ["DOMAIN-SUFFIX,google.com", "IP-CIDR,91.108.4.0/22", "DOMAIN-SUFFIX,conflict.test", "DOMAIN-SUFFIX,ads.test"],
            "reject": ["DOMAIN-SUFFIX,ads.test", "IP-CIDR,192.168.0.0/16"],
        }
        self.assertEqual(set(config["rule-providers"]), set(providers))
        cases = {
            "ads.test": ("REJECT", "reject"),
            "www.google.com": ("PROXY", "proxy"),
            "www.qq.com": ("DIRECT", "direct"),
            "192.168.1.1": ("DIRECT", "192.168.0.0/16"),
            "91.108.4.1": ("PROXY", "proxy"),
            "conflict.test": ("PROXY", "proxy"),
            "unknown.test": ("PROXY", "MATCH"),
        }
        for destination, expected in cases.items():
            with self.subTest(destination=destination):
                for rule in config["rules"]:
                    kind, value, *params = rule.split(",")
                    if kind == "RULE-SET":
                        if any(matches(item, destination) for item in providers[value]):
                            self.assertEqual((params[0], value), expected)
                            break
                    elif kind == "MATCH":
                        self.assertEqual((value, kind), expected)
                        break
                    elif matches(rule, destination):
                        self.assertEqual((params[0], value), expected)
                        break
                else:
                    self.fail("no rule matched")
