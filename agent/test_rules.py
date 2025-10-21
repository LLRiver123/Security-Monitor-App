import unittest

from agent.rules import suspicious_rule_structured


def make_event(event_id=None, data=None):
    return {"event_id": event_id, "time": None, "data": data or {}}


class TestRules(unittest.TestCase):

    def test_powershell_obfuscated(self):
        ev = make_event(data={
            "Image": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "-nop -w hidden -enc SGVsbG8=",
        })
        alerts = suspicious_rule_structured(ev)
        self.assertTrue(any("Obfuscated PowerShell" in a["message"] or "Obfuscated" in a["message"] for a in alerts))

    def test_network_external(self):
        ev = make_event(event_id=3, data={
            "SourceIp": "192.168.1.5",
            "DestinationIp": "8.8.8.8",
            "DestinationPort": "53",
        })
        alerts = suspicious_rule_structured(ev)
        self.assertTrue(any("external IP" in a["message"] or "External" in a["message"] or "8.8.8.8" in a["message"] for a in alerts))

    def test_execution_from_temp(self):
        ev = make_event(data={"Image": r"C:\\Users\\Alice\\AppData\\Local\\Temp\\evil.exe"})
        alerts = suspicious_rule_structured(ev)
        self.assertTrue(any("temporary" in a["message"].lower() or "temp" in a["message"].lower() for a in alerts))


if __name__ == "__main__":
    unittest.main()
