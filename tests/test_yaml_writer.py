from __future__ import annotations

import unittest

from ctf_generator.yaml_writer import dump_yaml


class YamlWriterTests(unittest.TestCase):
    def test_dump_yaml_handles_nested_mappings(self) -> None:
        text = dump_yaml(
            {
                "title": "Invoice Drift",
                "enabled": True,
                "items": [{"name": "first"}, {"name": "second"}],
            }
        )

        self.assertIn('title: "Invoice Drift"', text)
        self.assertIn("enabled: true", text)
        self.assertIn('-\n    name: "first"', text)


if __name__ == "__main__":
    unittest.main()
