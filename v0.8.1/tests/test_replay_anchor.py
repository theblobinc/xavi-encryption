import tempfile
import time
import unittest
from pathlib import Path

from xavi_duo_replay import ReplayError, ReplayGuard
from xavi_duo_replay_anchor import (
    CallbackReplayAnchor,
    ReplayAnchorError,
    ReplayClaimConflict,
    replay_anchor_key,
    replay_claim_id,
)


class MemoryReplayAnchor:
    def __init__(self):
        self.high = {}
        self.prepared = {}
        self.history = {}
        self.fail_commit_once = False
        self.calls = []

    def _receipt(self, operation, key, counter, claim_id, state, idempotent):
        return {
            "schema": "XAVI-DUO/REPLAY-ANCHOR-RECEIPT/v2",
            "status": "accepted",
            "operation": operation,
            "anchor_id": "test-anchor",
            "rollback_domain": "independent-test-domain",
            "key_id": key,
            "counter": counter,
            "high_water": self.high.get(key, 0),
            "claim_id": claim_id,
            "state": state,
            "idempotent": idempotent,
            "authority": False,
        }

    def callback(self, operation, key, counter, claim_id):
        self.calls.append((operation, key, counter, claim_id))
        high = self.high.get(key, 0)
        history = self.history.setdefault(key, {})
        pending = self.prepared.get(key)

        if operation == "prepare":
            if counter <= high:
                if history.get(counter) == claim_id:
                    return self._receipt(operation, key, counter, claim_id, "committed", True)
                raise ReplayClaimConflict("committed sequence belongs to another claim")
            if counter != high + 1:
                raise ReplayClaimConflict("sequence gap")
            if pending is not None:
                if pending == (counter, claim_id):
                    return self._receipt(operation, key, counter, claim_id, "prepared", True)
                raise ReplayClaimConflict("different claim already prepared")
            self.prepared[key] = (counter, claim_id)
            return self._receipt(operation, key, counter, claim_id, "prepared", False)

        if operation != "commit":
            raise ReplayAnchorError("unsupported operation")
        if counter <= high:
            if history.get(counter) == claim_id:
                return self._receipt(operation, key, counter, claim_id, "committed", True)
            raise ReplayClaimConflict("committed sequence belongs to another claim")
        if counter != high + 1 or pending != (counter, claim_id):
            raise ReplayClaimConflict("claim was not prepared")
        if self.fail_commit_once:
            self.fail_commit_once = False
            raise ReplayAnchorError("simulated transient commit failure")
        self.high[key] = counter
        history[counter] = claim_id
        self.prepared.pop(key, None)
        return self._receipt(operation, key, counter, claim_id, "committed", False)


def make_anchor(mem):
    return CallbackReplayAnchor(
        mem.callback,
        anchor_id="test-anchor",
        rollback_domain="independent-test-domain",
    )


class ReplayAnchorTests(unittest.TestCase):
    def test_high_assurance_requires_v2_anchor(self):
        with tempfile.TemporaryDirectory() as td:
            g = ReplayGuard(Path(td) / "replay.json").init()
            with self.assertRaises(ReplayError):
                g.claim("s", 1, "m1", int(time.time()) + 60, project_id="p", require_anchor=True)

    def test_out_of_order_request_does_not_advance_external_anchor(self):
        with tempfile.TemporaryDirectory() as td:
            mem = MemoryReplayAnchor()
            anchor = make_anchor(mem)
            g = ReplayGuard(Path(td) / "replay.json").init()
            expiry = int(time.time()) + 120
            g.claim("s", 1, "m1", expiry, project_id="p", anchor=anchor, require_anchor=True)
            key = replay_anchor_key("p", "s")
            self.assertEqual(mem.high[key], 1)
            calls_before = len(mem.calls)
            with self.assertRaisesRegex(ReplayError, "expected sequence 2"):
                g.claim("s", 3, "m3", expiry, project_id="p", anchor=anchor, require_anchor=True)
            self.assertEqual(mem.high[key], 1)
            self.assertEqual(len(mem.calls), calls_before)

    def test_commit_failure_leaves_recoverable_pending_claim(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "replay.json"
            mem = MemoryReplayAnchor()
            mem.fail_commit_once = True
            anchor = make_anchor(mem)
            g = ReplayGuard(p).init()
            expiry = int(time.time()) + 120
            with self.assertRaisesRegex(ReplayError, "pending claim retained"):
                g.claim("s", 1, "m1", expiry, project_id="p", anchor=anchor, require_anchor=True)
            row = __import__("json").loads(p.read_text())["s"]
            self.assertEqual(row["last_sequence"], 1)
            self.assertEqual(row["pending"]["phase"], "local-committed")
            recovered = g.claim("s", 1, "m1", expiry, project_id="p", anchor=anchor, require_anchor=True)
            self.assertTrue(recovered["recovered_pending"])
            self.assertEqual(mem.high[replay_anchor_key("p", "s")], 1)
            self.assertNotIn("pending", __import__("json").loads(p.read_text())["s"])

    def test_crash_after_external_prepare_before_local_commit_recovers(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "replay.json"
            mem = MemoryReplayAnchor()
            anchor = make_anchor(mem)
            g = ReplayGuard(p).init()
            expiry = int(time.time()) + 120
            key = replay_anchor_key("p", "s")
            claim_id = replay_claim_id("p", "s", 1, "m1", expiry)
            first = anchor.prepare(key, 1, claim_id)
            self.assertEqual(first["state"], "prepared")
            self.assertFalse(first["idempotent"])
            state = {
                "s": {
                    "last_sequence": 0,
                    "message_ids": [],
                    "pending": {
                        "schema": "XAVI-DUO/REPLAY-PENDING/v2",
                        "phase": "intent",
                        "project_id": "p",
                        "sequence": 1,
                        "message_id": "m1",
                        "expires_at": expiry,
                        "key_id": key,
                        "claim_id": claim_id,
                        "authority": False,
                    },
                }
            }
            p.write_text(__import__("json").dumps(state))
            p.chmod(0o600)
            recovered = g.claim("s", 1, "m1", expiry, project_id="p", anchor=anchor, require_anchor=True)
            self.assertTrue(recovered["recovered_pending"])
            self.assertEqual(mem.high[key], 1)
            row = __import__("json").loads(p.read_text())["s"]
            self.assertEqual(row["last_sequence"], 1)
            self.assertNotIn("pending", row)

    def test_full_local_snapshot_rollback_exact_replay_quarantines(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "replay.json"
            mem = MemoryReplayAnchor()
            anchor = make_anchor(mem)
            g = ReplayGuard(p).init()
            expiry = int(time.time()) + 120
            g.claim("s", 1, "m1", expiry, project_id="p", anchor=anchor, require_anchor=True)
            snapshot = p.read_bytes()
            g.claim("s", 2, "m2", expiry, project_id="p", anchor=anchor, require_anchor=True)
            p.write_bytes(snapshot)
            with self.assertRaisesRegex(ReplayError, "ahead of local state"):
                g.claim("s", 2, "m2", expiry, project_id="p", anchor=anchor, require_anchor=True)
            self.assertTrue(g.quarantine.exists())

    def test_full_local_snapshot_rollback_conflicting_claim_quarantines(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "replay.json"
            mem = MemoryReplayAnchor()
            anchor = make_anchor(mem)
            g = ReplayGuard(p).init()
            expiry = int(time.time()) + 120
            g.claim("s", 1, "m1", expiry, project_id="p", anchor=anchor, require_anchor=True)
            snapshot = p.read_bytes()
            g.claim("s", 2, "m2", expiry, project_id="p", anchor=anchor, require_anchor=True)
            p.write_bytes(snapshot)
            with self.assertRaisesRegex(ReplayError, "rollback/conflict"):
                g.claim("s", 2, "m2-conflict", expiry, project_id="p", anchor=anchor, require_anchor=True)
            self.assertTrue(g.quarantine.exists())

    def test_anchor_key_is_project_session_domain_separated(self):
        self.assertNotEqual(replay_anchor_key("p1", "s"), replay_anchor_key("p2", "s"))
        self.assertNotEqual(replay_anchor_key("p", "s1"), replay_anchor_key("p", "s2"))


if __name__ == "__main__":
    unittest.main()
