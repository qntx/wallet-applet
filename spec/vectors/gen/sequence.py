#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 QuantX
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generates spec/vectors/verify-sequence.json from spec/protocol.md §7.3, §9.2, §9.3, §9.5, §9.7,
§9.12–9.15 and §11.

A small model of the access-code rules (life, the failure count f, the session's waited and
verified state) and of the offer and pending-import state computes the expected inner status word
and the STATUS response after every step of each scripted sequence. Each sequence starts on a
LOADED card in a fresh session that is not verified, by the setup it names. Stdlib only; output is
canonical (json.dumps(obj, indent=2) + "\\n", ASCII).

Usage: python3 sequence.py [out.json]
"""
import json
import sys

L, F, W, I = 10, 3, 15, 400

SETUPS = {
    "create": (
        "The card under test is LOADED by CREATE with the right access hash (any 32-byte "
        "value; the wrong access hash is any other value), followed by a new OPEN: f = 0, "
        "waited = 0, not verified."
    ),
    "set": (
        "Two cards personalized under one CA: the member Y and the card under test X. Y is "
        "LOADED by CREATE P1 = 01 with the right access hash, any valid seed and ID(X) as the "
        "other member. X (BLANK) answers OFFER; Y exports to X (EXPORT P1 = 00 with X's "
        "certificate and that OFFER response, EXPORT P1 = 01 with the right access hash); X "
        "answers IMPORT P1 = 00 and P1 = 01 with 9000. Then a new OPEN on X: X is LOADED with "
        "Y's wallet (members Y, X), f = 0, waited = 0, not verified, offer = NONE."
    ),
}

STEP_RULES = (
    "After a step that has status the replayer sends STATUS in the current session of the "
    "card under test and compares its response with status (life(1) ‖ tries(1), §9.3); STATUS "
    "has no side effect on the card but, like every command that does not continue it, ends "
    "a pending import (§9.2), so steps that leave one for the next step have no status. A "
    "step with repeat n is sent n times, each answered with sw; status is checked after the "
    "last one. Codes: right is the access hash of the setup, wrong any other, new a third "
    "access hash. OFFER: lk new means the returned LK differs from every LK the card returned "
    "before, same that it equals the LK of the previous OFFER. EXPORT runs on the member Y, "
    "not on the card under test: a new OPEN on Y, VERIFY with the right code, EXPORT P1 = 00 "
    "with X's certificate and X's most recent OFFER response, then EXPORT P1 = 01 with the "
    "access hash named by code; both return sw, and the exports of a sequence are numbered "
    "1, 2, … in order. IMPORT0 sends IMPORT P1 = 00 with Y's certificate and the E ‖ sig_S of "
    "export number export (default: the latest); IMPORT1 sends IMPORT P1 = 01 with the ct ‖ "
    "tag of the export of the pending import, or of the latest export when there is none."
)

TEAR = (
    "after-T-FAIL: power is lost after the T-FAIL transaction of this VERIFY committed and "
    "before any later persistent write (§9.5 steps 5-9). The command has no response "
    "(sw torn); the replayer powers the card up, SELECTs the wallet applet and OPENs a new "
    "session before the STATUS check."
)


class Card:
    """The model of the card under test: life, f, the code that matches, the session's waited
    and verified state, the offer (with a counter naming each LK) and the pending import."""

    def __init__(self):
        self.life = "LOADED"
        self.f = 0
        self.code = "right"
        self.waited = 0
        self.verified = False
        self.offer = False
        self.lk = 1  # the set setup's LK; a create setup never published one
        self.lks = 1
        self.pending = None

    def status(self):
        self.pending = None  # STATUS does not continue a pending import (§9.2)
        if self.life == "BLANK":
            return "0100"
        return "02%02x" % max(L - self.f, 0)

    def erase(self):
        """T-ERASE (§4.3): BLANK, f = 0, offer = NONE."""
        self.life = "BLANK"
        self.f = 0
        self.offer = False

    def verify(self, code, tear):
        self.pending = None
        if self.life != "LOADED":
            return "6985"
        self.verified = False  # step 1
        if self.f >= L:  # step 2: re-entry after a lost T-ERASE
            self.erase()
            return "6983"
        if self.f >= F and self.waited < W:  # step 3: nothing written, waited kept
            return "6986"
        self.waited = 0  # step 4
        self.f += 1  # step 5, T-FAIL
        if tear:
            self.waited = 0  # power loss ends the session
            return "torn"
        if code == self.code:  # step 8, T-OK
            self.f = 0
            self.verified = True
            return "9000"
        if self.f == L:  # step 9
            self.erase()
            return "6983"
        return "63c%x" % (L - self.f)  # step 10

    def wait(self):
        self.pending = None
        if self.life != "LOADED":
            return "6985"
        self.waited = min(self.waited + 1, W)
        return "9000"

    def open(self):
        self.waited = 0
        self.verified = False
        self.pending = None
        return "9000"

    def erase_command(self):
        """ERASE (§9.7)."""
        self.pending = None
        if self.life != "LOADED":
            return "6985"
        if not self.verified:
            return "6982"
        self.erase()
        self.verified = False
        return "9000"

    def offer_command(self):
        """OFFER (§9.12): a new LK only when offer = NONE (T-OFFER)."""
        self.pending = None
        if self.offer:
            return "9000", "same"
        self.lks += 1
        self.lk = self.lks
        self.offer = True
        return "9000", "new"

    def import0(self, export):
        """IMPORT P1 = 00 (§9.14) with an export by the member Y: the signature binds the LK
        the export was made for."""
        self.pending = None  # P1 = 00 does not continue a pending import
        if not self.offer:
            return "6985"
        if export["lk"] != self.lk:
            return "6a80"
        self.pending = export
        return "9000"

    def import1(self):
        """IMPORT P1 = 01 (§9.14): T-INSTALL with the export's access hash."""
        export, self.pending = self.pending, None  # a continuation ends its own state
        if not self.offer or export is None:
            return "6985"
        self.life = "LOADED"
        self.f = 0
        self.code = export["code"]
        self.offer = False
        self.verified = False
        return "9000"


class Script:
    def __init__(self, name, description, setup="create"):
        self.card = Card()
        if setup == "create":
            self.card.lk = 0
            self.card.lks = 0
        self.exports = []
        self.seq = {"name": name, "description": description, "setup": setup, "steps": []}

    def _step(self, step, status=True):
        if status:
            step["status"] = self.card.status()
        self.seq["steps"].append(step)
        return self

    def offer(self):
        sw, lk = self.card.offer_command()
        return self._step({"command": "OFFER", "sw": sw, "lk": lk})

    def export(self, code):
        """Y exports to the card's most recent LK with the access hash `code`."""
        assert self.card.lk > 0
        self.exports.append({"lk": self.card.lk, "code": code})
        return self._step({"command": "EXPORT", "code": code, "sw": "9000"})

    def import0(self, export=None, status=False):
        step = {"command": "IMPORT0"}
        if export is not None:
            step["export"] = export
        step["sw"] = self.card.import0(self.exports[(export or len(self.exports)) - 1])
        return self._step(step, status)

    def import1(self):
        return self._step({"command": "IMPORT1", "sw": self.card.import1()})

    def erase(self):
        return self._step({"command": "ERASE", "sw": self.card.erase_command()})

    def verify(self, code, tear=None):
        step = {"command": "VERIFY", "code": code}
        if tear:
            step["tear"] = tear
        step["sw"] = self.card.verify(code, tear)
        return self._step(step)

    def wait(self, n=W):
        sws = {self.card.wait() for _ in range(n)}
        assert len(sws) == 1
        return self._step({"command": "WAIT", "repeat": n, "sw": sws.pop()})

    def open(self):
        return self._step({"command": "OPEN", "sw": self.card.open()})

    def wrong_to(self, f):
        """Wrong codes (with W waits once f >= F) until the count is f, or until the L-th
        failure erased the wallet."""
        while self.card.life == "LOADED" and self.card.f < f:
            if self.card.f >= F:
                self.wait()
            self.verify("wrong")
        return self

    def done(self):
        return self.seq


def sequences():
    out = []

    s = Script(
        "wrong-to-limit",
        "Wrong codes from f = 0 to L: three free attempts, then 6986 until W WAITs complete "
        "in the session (a refused VERIFY keeps waited), then one attempt per W WAITs; the "
        "L-th failure erases. Afterwards VERIFY and WAIT are refused in BLANK.",
    )
    s.verify("wrong").verify("wrong").verify("wrong")
    s.verify("wrong").wait(W - 1).verify("wrong").wait(1).verify("wrong")
    for _ in range(F + 1, L):
        s.wait().verify("wrong")
    s.verify("right").wait(1)
    out.append(s.done())

    for k in range(L):
        s = Script(
            "right-resets-at-f-%d" % k,
            "k = %d wrong codes, then the right code resets f to 0; the free attempts "
            "return." % k,
        )
        s.wrong_to(k)
        if k >= F:
            s.wait()
        s.verify("right").verify("wrong")
        out.append(s.done())

    s = Script(
        "right-needs-wait",
        "Once f >= F the wait applies to the right code too; nothing is written while it is "
        "refused.",
    )
    s.wrong_to(F).verify("right").wait().verify("right")
    out.append(s.done())

    s = Script(
        "waited-lost-on-open",
        "waited is session state: a new OPEN discards completed WAITs.",
    )
    s.wrong_to(F).wait().open().verify("wrong").wait().verify("wrong")
    out.append(s.done())

    s = Script(
        "wait-beyond-W",
        "waited saturates at W; one VERIFY consumes all of it, so the next attempt needs W "
        "new WAITs.",
    )
    s.wrong_to(F).wait(W + 5).verify("wrong").verify("wrong")
    out.append(s.done())

    s = Script(
        "torn-right-code-counts",
        "The right code with power lost after T-FAIL: the attempt stays counted; the next "
        "right code resets.",
    )
    s.verify("right", tear="after-T-FAIL").verify("right")
    out.append(s.done())

    s = Script(
        "tries-zero",
        "Power lost after the L-th T-FAIL, before T-ERASE: STATUS reports tries = 0 and the "
        "next VERIFY erases at step 2 without comparing, even with the right code and no "
        "WAIT.",
    )
    s.wrong_to(L - 1).wait().verify("wrong", tear="after-T-FAIL").verify("right")
    out.append(s.done())

    s = Script(
        "offer-repeated",
        "OFFER with a valid offer returns the same LK and writes nothing; the offer survives "
        "a new session.",
    )
    s.offer().offer().open().offer()
    out.append(s.done())

    s = Script(
        "reseal-resets-fails",
        "A re-seal of a LOADED card from the member Y with a new access hash resets f; the "
        "old code no longer matches, the new one does.",
        setup="set",
    )
    s.wrong_to(F + 1).offer().export("new").import0().import1()
    s.verify("right").verify("new")
    out.append(s.done())

    s = Script(
        "import-after-install",
        "After a committed install offer = NONE: IMPORT P1 = 00 with the same export returns "
        "6985; after a new OFFER the export made for the earlier offer is refused.",
        setup="set",
    )
    s.offer().export("new").import0().import1()
    s.import0(status=True).import1()
    s.offer().import0(export=1, status=True)
    out.append(s.done())

    s = Script(
        "import-pending-ended",
        "A pending import ends at any command that does not continue it (here STATUS); IMPORT "
        "P1 = 00 can be repeated with the same export while offer = VALID.",
        setup="set",
    )
    s.offer().export("new").import0(status=True).import1()
    s.import0().import0().import1().verify("new")
    out.append(s.done())

    s = Script(
        "limit-erased-reprovision",
        "A card erased by the failure limit is re-provisioned from the member Y: BLANK, "
        "OFFER, export, IMPORT; the new code then matches.",
        setup="set",
    )
    s.wrong_to(L).offer().export("new").import0().import1().verify("new")
    out.append(s.done())

    s = Script(
        "erase-ends-offer",
        "ERASE ends a valid offer: the export made for it is refused with 6985, and with 6a80 "
        "after a new OFFER.",
        setup="set",
    )
    s.offer().export("new").verify("right").erase()
    s.import0(status=True).offer().import0(export=1, status=True)
    out.append(s.done())

    return out


def main():
    doc = {
        "constants": {"L": L, "F": F, "W": W, "I": I},
        "setups": SETUPS,
        "stepRules": STEP_RULES,
        "tear": TEAR,
        "sequences": sequences(),
    }
    text = json.dumps(doc, indent=2, ensure_ascii=True) + "\n"
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w", encoding="ascii", newline="\n") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
