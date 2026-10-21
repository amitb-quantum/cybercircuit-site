#!/usr/bin/env python3
"""Independent verifier for CircuitBreaker evidence bundle format v1, written from spec.md only.
Usage: python verifier.py BUNDLE_DIR --keys gateway-keys.pub.json --log-key rekor-log.pub.pem
                          [--receipts receipts.jsonl] [--online]
Deps: cryptography, slh-dsa (pure-python FIPS 205 implementation, verify_pure)."""
import argparse, base64, hashlib, json, os, re, sys, urllib.request
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
try:
    import slhdsa
    HAVE_SLH = True
except Exception:
    HAVE_SLH = False

def sha(b): return hashlib.sha256(b).digest()
def shx(b): return hashlib.sha256(b).hexdigest()
HEX64 = re.compile(r'^[0-9a-f]{64}$')
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
CTX = b"circuitbreaker-checkpoint-v1"

class R:
    def __init__(s): s.rows = []
    def add(s, sec, name, ok, detail=""):
        s.rows.append((sec, name, ok, detail)); return ok
    def first_fail(s):
        for r in s.rows:
            if r[2] is False: return r
        return None

def read_lines(path, ascii_only=True):
    """Return list of raw line bytes (without \n); raise ValueError on framing problems."""
    data = open(path, 'rb').read()
    if not data.endswith(b"\n"): raise ValueError("file does not end with \\n")
    lines = data[:-1].split(b"\n")
    if any(l == b"" for l in lines): raise ValueError("blank line")
    data.decode('ascii' if ascii_only else 'utf-8')
    return lines

def ecdsa_pub_from_point(pt):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pt)

def ecdsa_ok(pub, sig, msg):
    try: pub.verify(sig, msg, ec.ECDSA(hashes.SHA256())); return True
    except (InvalidSignature, ValueError): return False

def canon_statement(st):
    d, c = st["decision"], st["control"]
    o = {"schema_version": st["schema_version"], "gateway_key_id": st["gateway_key_id"],
         "sequence": st["sequence"], "reason": st["reason"],
         "decision": {"journal_id": d["journal_id"], "sequence": d["sequence"], "head_sha256": d["head_sha256"],
                      "epoch": d["epoch"], "state": d["state"]},
         "control": {"journal_id": c["journal_id"], "sequence": c["sequence"], "head_sha256": c["head_sha256"]},
         "previous_checkpoint_sha256": st["previous_checkpoint_sha256"], "wall_time_unix_ms": st["wall_time_unix_ms"]}
    # exact key sets required
    if set(st) != set(o) or set(d) != set(o["decision"]) or set(c) != set(o["control"]):
        raise ValueError("statement has unexpected/missing keys")
    return json.dumps(o, separators=(",", ":"), ensure_ascii=True).encode()

def journal(path, label, gen_dom, rec_dom, fmt, rep, sec, is_decision):
    """Verify a hash-chained journal. Returns (journal_id, heads list [H0..Hn], bodies) or None."""
    try: lines = read_lines(path)
    except Exception as e:
        rep.add(sec, f"{label}: file framing (UTF-8/ASCII, one obj per line, trailing \\n)", False, str(e)); return None
    rep.add(sec, f"{label}: file framing", True)
    hdr = lines[0]
    try:
        h = json.loads(hdr)
        ok = list(h.keys()) == ["format", "journal_id"] and h["format"] == fmt and bool(UUID.match(h["journal_id"])) \
             and hdr == json.dumps(h, separators=(",", ":")).encode()
    except Exception: ok = False
    if not rep.add(sec, f"{label}: header format/journal_id", ok, hdr.decode()[:120]): return None
    jid = h["journal_id"]
    heads = [shx(gen_dom + hdr)]
    bodies = []
    pre, suf_re = b'{"body":', re.compile(rb',"sha256":"([0-9a-f]{64})"\}$')
    bad = None
    for n, ln in enumerate(lines[1:], 1):
        m = suf_re.search(ln)
        if not ln.startswith(pre) or not m: bad = (n, "line shape"); break
        bb = ln[len(pre):m.start()]
        try: body = json.loads(bb); json.loads(ln)
        except Exception: bad = (n, "body not JSON"); break
        if body.get("format") != fmt or body.get("sequence") != n or type(body.get("sequence")) is not int:
            bad = (n, "format/sequence"); break
        if is_decision:
            p = body.get("payload")
            if not isinstance(p, dict) or p.get("sequence") != n: bad = (n, "payload.sequence"); break
            if body.get("decision_id") != f"{jid}:{n:016x}": bad = (n, "decision_id"); break
        if body.get("previous_sha256") != heads[-1]: bad = (n, "previous_sha256 != previous head"); break
        dig = m.group(1).decode()
        if dig != shx(rec_dom + bb): bad = (n, "sha256 != SHA256(domain||BODY_BYTES)"); break
        heads.append(dig); bodies.append(body)
    rep.add(sec, f"{label}: record chain ({len(lines)-1} records: format, sequence, ids, previous_sha256, sha256)",
            bad is None, "" if bad is None else f"record {bad[0]}: {bad[1]}")
    if bad: return None
    return jid, heads, bodies

def load_keys(path):
    k = json.load(open(path))
    slh = bytes.fromhex(k["slh_dsa_sha2_128f"]); pt = bytes.fromhex(k["ecdsa_p256"])
    return k, slh, pt

def verify_checkpoint(cp, raw_stmt, keys, rep, sec, label):
    """§4.4 checks 1-5. raw_stmt: exact bytes from file, or None (receipt: re-encode)."""
    k, slh_pk, pt = keys
    st = cp.get("statement")
    ok1 = isinstance(st, dict) and st.get("schema_version") == "circuitbreaker.checkpoint.v1" and st.get("gateway_key_id") == k["gateway_key_id"]
    rep.add(sec + "#1", f"{label}: schema_version & gateway_key_id == trusted", ok1)
    try:
        canon = canon_statement(st)
        sb = raw_stmt if raw_stmt is not None else canon
        canon_ok = raw_stmt is None or raw_stmt == canon
    except Exception as e:
        rep.add("4.3", f"{label}: canonical STATEMENT_BYTES", False, str(e)); return False
    rep.add("4.3", f"{label}: statement bytes in canonical key order/compact", canon_ok)
    ok2 = cp.get("statement_sha256") == shx(sb)
    rep.add(sec + "#2", f"{label}: statement_sha256 == SHA256(STATEMENT_BYTES)", ok2)
    try: e_ok = ecdsa_ok(ecdsa_pub_from_point(pt), bytes.fromhex(cp["ecdsa_p256_sha256"]), sb)
    except Exception: e_ok = False
    rep.add(sec + "#3", f"{label}: ECDSA P-256/SHA-256 signature", e_ok)
    if HAVE_SLH:
        try:
            sig = bytes.fromhex(cp["slh_dsa_sha2_128f"])
            pk = slhdsa.PublicKey((slh_pk[:16], slh_pk[16:]), slhdsa.sha2_128f)
            s_ok = len(sig) == 17088 and pk.verify_pure(sb, sig, CTX)
        except Exception as ex: s_ok = False
        rep.add(sec + "#4", f"{label}: SLH-DSA-SHA2-128f pure, ctx, 17088 bytes", bool(s_ok))
        rep.add(sec + "#5", f"{label}: both signatures verify", bool(e_ok and s_ok))
    else:
        rep.add(sec + "#4", f"{label}: SLH-DSA", None, "NOT RUN: no SLH-DSA library")
        rep.add(sec + "#5", f"{label}: both signatures", None, "NOT RUN")
    return ok1 and canon_ok and ok2 and e_ok and (HAVE_SLH and s_ok)

def inclusion_root(index, size, leaf, hashes_):
    # RFC 9162 2.1.3.2
    if index >= size: return None
    fn, sn, r = index, size - 1, leaf
    for p in hashes_:
        if sn == 0: return None
        if fn & 1 or fn == sn:
            r = sha(b"\x01" + p + r)
            if not fn & 1:
                while fn != 0 and not fn & 1: fn >>= 1; sn >>= 1
        else:
            r = sha(b"\x01" + r + p)
        fn >>= 1; sn >>= 1
    return r if sn == 0 else None

def check_anchor(a, log_pub, log_spki, gw_pt, bundle_cps, rep, label, online):
    e = a["entry"]; ip = e["verification"]["inclusionProof"]
    rep.add("6#1", f"{label}: logID == SHA256(trusted log SPKI)", e["logID"] == shx(log_spki))
    set_msg = json.dumps({"body": e["body"], "integratedTime": e["integratedTime"], "logID": e["logID"],
                          "logIndex": e["logIndex"]}, sort_keys=True, separators=(",", ":")).encode()
    rep.add("6#2", f"{label}: signedEntryTimestamp", ecdsa_ok(log_pub, base64.b64decode(e["verification"]["signedEntryTimestamp"]), set_msg))
    body = base64.b64decode(e["body"]); leaf = sha(b"\x00" + body)
    u = a["uuid"]
    rep.add("6#3", f"{label}: uuid (64/80 hex) ends with leaf hash", len(u) in (64, 80) and u.endswith(leaf.hex()))
    root = inclusion_root(ip["logIndex"], ip["treeSize"], leaf, [bytes.fromhex(h) for h in ip["hashes"]])
    rep.add("6#4", f"{label}: inclusion proof -> rootHash", root is not None and root.hex() == ip["rootHash"])
    note = ip["checkpoint"]; ok5 = False; det = ""
    try:
        text, sigs = note.split("\n\n", 1); text += "\n"
        tl = text.split("\n")
        hint = bytes.fromhex(e["logID"])[:4]
        sig_ok = False
        for sl in sigs.split("\n"):
            if not sl.startswith("\u2014 "): continue
            raw = base64.b64decode(sl.rsplit(" ", 1)[1])
            if raw[:4] == hint and ecdsa_ok(log_pub, raw[4:], text.encode()): sig_ok = True
        size_ok = int(tl[1]) == ip["treeSize"] and base64.b64decode(tl[2]).hex() == ip["rootHash"]
        ok5 = sig_ok and size_ok; det = f"sig={sig_ok} size/root={size_ok}"
    except Exception as ex: det = str(ex)
    rep.add("6#5", f"{label}: signed tree head note", ok5, det)
    cp = bundle_cps.get(a["checkpoint_sequence"])
    ok6 = False; det = ""
    try:
        b = json.loads(body)
        sp = b["spec"]
        pem = base64.b64decode(sp["signature"]["publicKey"]["content"])
        spki = serialization.load_pem_public_key(pem).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        conds = {"apiVersion": b.get("apiVersion") == "0.0.1", "kind": b.get("kind") == "hashedrekord",
                 "alg": sp["data"]["hash"]["algorithm"] == "sha256",
                 "hash==stmt": cp is not None and sp["data"]["hash"]["value"] == cp["statement_sha256"],
                 "sig==cp ecdsa": cp is not None and base64.b64decode(sp["signature"]["content"]) == bytes.fromhex(cp["ecdsa_p256_sha256"]),
                 "pubkey==gateway": spki == SPKI_PREFIX + gw_pt and b"PUBLIC KEY" in pem}
        ok6 = all(conds.values()); det = ",".join(k for k, v in conds.items() if not v)
    except Exception as ex: det = str(ex)
    rep.add("6#6", f"{label}: body binds to checkpoint", ok6, det)
    rep.add("6#7", f"{label}: bundle checkpoint {a['checkpoint_sequence']} has same statement_sha256",
            cp is not None and cp["statement_sha256"] == a["statement_sha256"])
    if online:
        try:
            url = f"{a['log_url'].rstrip('/')}/api/v1/log/entries/{u}"
            live = json.load(urllib.request.urlopen(url, timeout=30))
            le = next(iter(live.values()))
            same = all(le.get(k) == e[k] for k in ("body", "integratedTime", "logID", "logIndex"))
            rep.add("6 (online)", f"{label}: live Rekor entry equals stored (body,integratedTime,logID,logIndex)", same)
        except Exception as ex:
            rep.add("6 (online)", f"{label}: live Rekor fetch", None, f"NOT RUN: {ex}")

def verify(bdir, keys_path, logkey_path, receipts_path, online):
    rep = R()
    req = ["decision.jsonl", "control.jsonl", "checkpoints.jsonl", "gateway-keys.pub.json"]
    miss = [f for f in req if not os.path.exists(os.path.join(bdir, f))]
    rep.add("1", "required files present", not miss, ",".join(miss))
    keys = load_keys(keys_path)
    k = keys[0]
    rep.add("4.1", "trusted gateway_key_id == SHA256(domain||u32be(32)||slh_pk||ecdsa_point)",
            k["gateway_key_id"] == shx(b"circuitbreaker-gateway-keys-v1\0" + (32).to_bytes(4, "big") + keys[1] + keys[2])
            and k["schema_version"] == "circuitbreaker.gateway-keys.v1" and len(keys[1]) == 32 and len(keys[2]) == 65 and keys[2][0] == 4)
    try: bk = json.load(open(os.path.join(bdir, "gateway-keys.pub.json")))
    except Exception: bk = {}
    rep.add("1/7", "bundle gateway keys equal trusted (same gateway_key_id)", bk.get("gateway_key_id") == k["gateway_key_id"],
            "" if bk == k else "(full JSON differs)" if bk.get("gateway_key_id") == k["gateway_key_id"] else "")
    dj = journal(os.path.join(bdir, "decision.jsonl"), "decision", b"circuitbreaker.m2.genesis\0", b"circuitbreaker.m2.record\0",
                 "circuitbreaker-m2.1", rep, "2", True)
    cj = journal(os.path.join(bdir, "control.jsonl"), "control", b"circuitbreaker-control/genesis\0", b"circuitbreaker-control/entry\0",
                 "circuitbreaker-control.1", rep, "3", False)
    if cj:
        kinds = {"tripped","kill","alarm","checkpoint","anchor","reset","model_use","model_uses_suppressed","peer_rejected","peers_suppressed","scope_lost","daemon_lost"}
        badk = [i+1 for i, b in enumerate(cj[2]) if not isinstance(b.get("entry"), dict) or b["entry"].get("kind") not in kinds]
        rep.add("3", "control: entry.kind in allowed set", not badk, f"records {badk}" if badk else "")
    # checkpoints
    cps = []
    try:
        lines = read_lines(os.path.join(bdir, "checkpoints.jsonl")); rep.add("4.2", "checkpoints: file framing", True)
    except Exception as ex:
        lines = []; rep.add("4.2", "checkpoints: file framing", False, str(ex))
    for i, ln in enumerate(lines, 1):
        try:
            cp = json.loads(ln)
            okk = list(cp.keys()) == ["statement", "statement_sha256", "slh_dsa_sha2_128f", "ecdsa_p256_sha256"]
            pre = b'{"statement":'; idx = ln.rfind(b',"statement_sha256":')
            raw = ln[len(pre):idx]
            okk = okk and ln.startswith(pre) and json.loads(raw) == cp["statement"]
        except Exception: okk = False; cp = None
        rep.add("4.2", f"checkpoint {i}: line keys/order", okk)
        if not cp: continue
        verify_checkpoint(cp, raw, keys, rep, "4.4", f"checkpoint {i}")
        cps.append(cp)
    # 4.5
    ok_seq = all(cp["statement"]["sequence"] == i for i, cp in enumerate(cps, 1))
    rep.add("4.5", "chain: statement.sequence == k", ok_seq and len(cps) == len(lines) and len(cps) > 0)
    prev_ok = all(cp["statement"]["previous_checkpoint_sha256"] == ("0"*64 if i == 0 else cps[i-1]["statement_sha256"]) for i, cp in enumerate(cps))
    rep.add("4.5", "chain: previous_checkpoint_sha256 links", prev_ok)
    jid_ok = bool(dj and cj) and all(cp["statement"]["decision"]["journal_id"] == dj[0] and cp["statement"]["control"]["journal_id"] == cj[0] for cp in cps)
    rep.add("4.5", "chain: journal_ids constant & equal journal headers", jid_ok)
    mono = all(cps[i]["statement"][j]["sequence"] >= cps[i-1]["statement"][j]["sequence"] for i in range(1, len(cps)) for j in ("decision", "control"))
    rep.add("4.5", "chain: decision/control sequences never decrease", mono)
    # 4.6
    if dj and cj:
        bad = []
        for i, cp in enumerate(cps, 1):
            d, c = cp["statement"]["decision"], cp["statement"]["control"]
            if not (0 <= d["sequence"] < len(dj[1]) and dj[1][d["sequence"]] == d["head_sha256"]): bad.append(f"cp{i} decision")
            if not (0 <= c["sequence"] < len(cj[1]) and cj[1][c["sequence"]] == c["head_sha256"]): bad.append(f"cp{i} control")
        rep.add("4.6", "heads match journals (decision H(seq), control C(seq))", not bad, ", ".join(bad))
        last = cps[-1]["statement"] if cps else None
        if last:
            bk_ = lambda e: e["kind"] in ("checkpoint", "anchor") or (e["kind"] == "alarm" and e.get("event") == "checkpoint")
            sealed = last["decision"]["sequence"] == len(dj[2]) and all(bk_(b["entry"]) for b in cj[2][last["control"]["sequence"]:])
            rep.add("4.7", "sealed (informational, not a validity check)", "info", "sealed" if sealed else "NOT sealed")
    else:
        rep.add("4.6", "heads match journals", None, "NOT RUN: journal chain failed")
    bycp = {cp["statement"]["sequence"]: cp for cp in cps}
    log_pub = serialization.load_pem_public_key(open(logkey_path, "rb").read())
    log_spki = log_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    # 5 receipts
    if receipts_path:
        for ri, ln in enumerate(read_lines(receipts_path, ascii_only=False), 1):
            o = json.loads(ln)
            if o.get("schema_version") == "circuitbreaker.alarm.v1":
                if o.get("event") != "checkpoint":
                    rep.add("5", f"receipt {ri}: alarm event={o.get('event')} (no checkpoint, skipped)", "info"); continue
                cp = o["checkpoint"]
            elif o.get("schema_version") == "circuitbreaker.rekor-anchor.v1":
                check_anchor(o, log_pub, log_spki, keys[2], bycp, rep, f"receipt {ri} (anchor)", online); continue
            elif "statement" in o: cp = o
            else:
                rep.add("5", f"receipt {ri}: unknown kind", False); continue
            verify_checkpoint(cp, None, keys, rep, "5#1/4.4", f"receipt {ri}")
            seq = cp["statement"]["sequence"]; b = bycp.get(seq)
            rep.add("5#2", f"receipt {ri}: bundle has checkpoint seq {seq}", b is not None)
            rep.add("5#3", f"receipt {ri}: same statement_sha256 as bundle cp {seq}", b is not None and b["statement_sha256"] == cp["statement_sha256"],
                    "" if b is None else f"receipt {cp['statement_sha256'][:16]}.. bundle {b['statement_sha256'][:16]}..")
    # 6 anchors
    ap = os.path.join(bdir, "rekor-anchors.jsonl")
    if os.path.exists(ap):
        anchors = [json.loads(l) for l in read_lines(ap, ascii_only=False)]
        for i, a in enumerate(anchors, 1):
            rep.add("6", f"anchor {i}: schema_version", a.get("schema_version") == "circuitbreaker.rekor-anchor.v1")
            check_anchor(a, log_pub, log_spki, keys[2], bycp, rep, f"anchor {i}", online)
        seqs = [a["checkpoint_sequence"] for a in anchors]
        rep.add("6#7", "anchors in increasing checkpoint_sequence, single log_url",
                all(seqs[i] > seqs[i-1] for i in range(1, len(seqs))) and len({a["log_url"] for a in anchors}) <= 1)
        if cj:
            miss = []
            for b in cj[2]:
                e = b["entry"]
                if e["kind"] == "anchor" and e.get("outcome") == "anchored":
                    if not any(a["checkpoint_sequence"] == e.get("checkpoint_sequence") and a["entry"]["logIndex"] == e.get("log_index") for a in anchors):
                        miss.append(f"ctl rec {b['sequence']} (cp {e.get('checkpoint_sequence')}, idx {e.get('log_index')})")
            rep.add("6#8", "every control 'anchored' record has matching anchor line", not miss, "; ".join(miss))
    return rep

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundles", nargs="+"); ap.add_argument("--keys", required=True); ap.add_argument("--log-key", required=True)
    ap.add_argument("--receipts"); ap.add_argument("--online", action="store_true")
    a = ap.parse_args()
    for b in a.bundles:
        rep = verify(b, a.keys, a.log_key, a.receipts, a.online)
        print(f"===== {b}")
        for sec, name, ok, det in rep.rows:
            st = {True: "PASS", False: "FAIL", None: "NOT RUN"}.get(ok, "INFO")
            print(f"  [{st:7}] §{sec:9} {name}" + (f"  -- {det}" if det else ""))
        ff = rep.first_fail(); nr = [r for r in rep.rows if r[2] is None]
        if ff: print(f"  VERDICT: INVALID — first failing check §{ff[0]}: {ff[1]} {ff[3]}")
        elif nr: print(f"  VERDICT: INCONCLUSIVE ({len(nr)} checks not run)")
        else: print("  VERDICT: VALID")
if __name__ == "__main__": main()
