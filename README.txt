================================================================================
 ProVerif 2.04 CRYPTANALYSIS SUITE
 Huang et al., HECC-based AKA for UAV-enabled SAR Networks
 Companion to: Analysis-3-revised.tex
 Target platform: ProVerif 2.04, Kali Linux x64
================================================================================

HOW TO RUN
----------
  for f in Huang-eCK-*.pv; do
      echo "===== $f ====="; proverif "$f" | tee "LOG-${f%.pv}.txt"
  done

--------------------------------------------------------------------------------
 1. EMULATING THE eCK MODEL IN ProVerif
--------------------------------------------------------------------------------
ProVerif's native adversary is Dolev-Yao: it controls the network but has no
oracle for revealing a party's secrets.  The eCK model adds exactly that.  The
standard practice -- which we follow and document here so a referee can audit
it -- is to encode the eCK oracles with applied-pi constructs:

  eCK oracle                  ProVerif encoding
  --------------------------  ------------------------------------------------
  EphemeralKeyReveal(P)       out(h_leak, s2b(omega_P)) in PHASE 0.
                              h_leak is a PUBLIC channel, so the reveal is
                              concurrent with the session -- the conservative
                              reading.  Kept on a SEPARATE channel from the
                              long-term corruption so that MIXED combinations
                              are expressible; this is the whole point, since
                              the mixed case is what eCK permits and CK does not.

  Corrupt(P)                  phase 1; out(h_ch, s2b(alpha_P)).
                              Placing corruption in a later phase separates
                              "secret during the session" (phase-0 query) from
                              "secret after compromise" (phase-1 query), so one
                              run reports both verdicts.

  SessionKeyReveal            not needed: we never reveal the test key.

  Test(sid*)                  out(h_ch, hoplus(secret_sk, SK)).  secret_sk is a
                              private constant; recovering it is equivalent to
                              reconstructing SK.  "attacker(secret_sk)" is then
                              exactly the Test-query advantage.

  Freshness predicate         NOT automatic -- it is our obligation.  Each file
                              states which secrets are revealed and argues that
                              the test session remains fresh.  See section 2.

--------------------------------------------------------------------------------
 2. THE MATCHED-SESSION DISCIPLINE  (the most important modelling decision)
--------------------------------------------------------------------------------
eCK freshness forbids corrupting the peer of a test session that has NO matching
session.  A model that lets the adversary SUPPLY the peer's ephemeral commitment
therefore silently leaves the fresh regime, and any "attack" it finds is a
modelling artefact rather than an eCK violation.

We enforce matching sessions by delivering the two ephemeral commitments over
DIRECTED private channels -- c_u2v (initiator to responder) and c_v2u (responder
to initiator) -- while still PUBLISHING the entire transcript on the public
channel h_ch.

The channels MUST be directed.  Our first draft used a single private channel
for both directions, and ProVerif duly delivered one initiator's Psi_1 to
ANOTHER INITIATOR's Psi_2 input.  The "peer ephemeral" was then a second
omega_u, which is leaked on h_leak, producing a derivation that is not a real
attack: File 3 reported "cannot be proved" on exactly such a path (see the
derivation step attacker_p1(hexp(hexp(h_g,omega_u_1),omega_u_2)) -- two
initiator ephemerals, no omega_v).  File 4 escaped the problem only by accident,
because in repair R2 the initiator sends a 3-tuple and expects a 2-tuple, so the
self-delivery fails on arity.  Directed channels remove the hazard by
construction.  The adversary thus observes exactly what a real eCK adversary
observes, and may still inject anything it likes, but cannot masquerade as the
peer's own commitment inside the test session.

This is not a theoretical nicety.  An earlier version of File 5 omitted the
discipline and reported a forward-secrecy "break"; the derivation showed the
adversary injecting its own Omega_v.  Restoring the discipline turns the verdict
to "true", which is the correct result and is what Proposition 2 of the analysis
now claims.  We report that negative result rather than the flattering one.

--------------------------------------------------------------------------------
 3. FILE MAP AND EXPECTED VERDICTS
--------------------------------------------------------------------------------
  FILE                                CLAIM                    EXPECTED / OBSERVED
  ----------------------------------  -----------------------  --------------------
  1 Huang-eCK-1-correctness.pv        Thm 1 (correctness)      not event(evU_accept)
                                                               expect TRUE (unreachable)
                                                               [run pending]
  2 Huang-eCK-2-correctness-control   control for Thm 1        FALSE (reachable) CONFIRMED
  3 Huang-eCK-3-eck-R1.pv             Thm 3, repair R1         expect phase1 FALSE
                                                               [v1 and v2 both returned
                                                               "cannot be proved"; file
                                                               rewritten as a hard-wired
                                                               single test session --
                                                               RE-RUN REQUIRED]
  4 Huang-eCK-4-eck-R2.pv             Thm 3, repair R2         phase1 FALSE   CONFIRMED
  5 Huang-eCK-5-pfs-survives.pv       Prop 2 (NEGATIVE)        phase1 TRUE    CONFIRMED
  6 Huang-eCK-6-forgery.pv            Thm 2 (forgery)          agreement FALSE CONFIRMED
                                                               inj-agreement FALSE CONFIRMED
  7 Huang-eCK-7-forgery-control.pv    control for Thm 2        agreement TRUE  CONFIRMED
  8 Huang-eCK-8-anonymity.pv          Thm 4 (linkability)      both probes FALSE CONFIRMED
  9 Huang-eCK-9-survives-capture.pv   Survives item 3 (NEG.)   secrecy TRUE   CONFIRMED

RESULTS OBTAINED (ProVerif 2.04, Kali x64).  Files 4-9 have been executed and
every verdict matched the prediction.  Two points deserve emphasis.

  (a) File 6 did not merely report "forgery exists" -- its derivation
      reconstructs Theorem 2 TERM FOR TERM:
          step  1  attacker(x)                          (forger picks p)
          step  9  hh((IDu,Cr_u,A_u,Xu,mNu))            (challenge c)
          step 11  sadd(Cr_u, smul(c,x))                (Lambda := Cr + c.p)
          step 13  mkring(hexp(h_g,x), hexp(h_g,alpha_u)) (ring := p.D - A_u)
      This is the strongest possible corroboration of a hand-written attack:
      the tool found OUR attack, not merely SOME attack.

  (b) Files 6 and 7 differ ONLY in the verification equation, and the verdict
      flips FALSE -> TRUE.  This mechanically isolates the root cause as the
      SHAPE of the relation (the challenge multiplying an adversary-chosen
      point) and refutes the more obvious diagnosis, "incomplete Fiat-Shamir".
      See section 4.

A NOTE ON QUERY PHASES, learned from the runs.  ProVerif evaluates an unphased
"query attacker(M)" at the MAXIMAL phase of the process.  Our first draft of
Files 3-5 wrote both an unphased and a phase-1 query, expecting a phase-0 /
phase-1 pair; the two in fact collapse to identical phase-1 verdicts, which is
why the summaries list the same line twice.  The break/survival verdicts are
unaffected, but the files have been corrected so that they do not claim a
phase-0 result that was never tested.  To certify phase-0 secrecy, comment out
the "phase 1" process and re-run.

READING THE VERDICTS.  For a reachability query "query event(e)", ProVerif
proves the NEGATION: "RESULT not event(e) is true" means the event is
UNREACHABLE.  File 1 therefore expects "is true" and File 2 expects "is false" --
this inversion is deliberate and is the whole content of Theorem 1.

--------------------------------------------------------------------------------
 4. THE CONTROL FILES, AND A CORRECTION WE MADE TO OURSELVES
--------------------------------------------------------------------------------
Files 2 and 7 exist so that a referee can see the defect ISOLATED: each is
identical to the file it controls except for one edit, and the verdict flips.

File 7 deserves a note.  Our first draft of the analysis attributed the forgery
to an incomplete Fiat-Shamir transform (the commitment being absent from the
challenge hash), and the control was going to be "put the commitment into the
hash".  On re-derivation this is WRONG: the forger fixes ring := p.D - A BEFORE
evaluating the challenge, so hashing the commitment changes nothing.  The actual
defect is the SHAPE of the equation -- the challenge multiplies the
adversary-chosen point (ring + A) instead of the certified key A.  File 7 now
controls for that, using the correct Schnorr form Lam.D = ring + c.A, and the
analysis document (Remark "Root cause") was corrected to match.  We record the
error here rather than quietly fixing it.

--------------------------------------------------------------------------------
 5. MODELLING CONVENTIONS
--------------------------------------------------------------------------------
  * HECC scalar multiplication a.P  ->  hexp, with the commuting DH equation.
  * XOR -> hoplus, self-inverse.  Used only as a secrecy probe.
  * sadd is a FREE symbol: no equation makes sadd(w,w*) equal w.  This is what
    makes File 1's key mismatch genuine rather than assumed.
  * Files 6 and 7 model the point equation FAITHFULLY rather than abstracting it
    to a hash token, using three linear equations:
        padd(hexp(g,x),hexp(g,y)) = hexp(g,sadd(x,y))
        pscal(c,hexp(g,x))        = hexp(g,smul(c,x))
        padd(mkring(T,A),A)       = T
    The last encodes ring := T - A.  Point subtraction is a PUBLIC group
    operation, so granting the attacker mkring grants it nothing it does not
    already have in the real group.  The DH commuting equation is deliberately
    OMITTED from Files 6/7 (it is irrelevant to signatures) to keep the
    equational theory small and improve termination.
  * Certificate scalars Cr_u, Cr_v are published in Files 3,4,5,6,7,9.  This is
    deliberate and conservative: the analysis shows Cr_u is held by every peer
    the target has contacted, so withholding it would understate the adversary.

--------------------------------------------------------------------------------
 6. CAVEAT -- PLEASE READ BEFORE CITING
--------------------------------------------------------------------------------
These models were written and hand-audited (syntax, parenthesis balance, type
discipline, and a line-by-line derivation of each expected verdict) but were NOT
executed here: no ProVerif binary is available in the authoring environment.
Run them on your Kali box and paste the ACTUAL output into the manuscript.  Do
not report a verdict you have not reproduced.

If a run disagrees with the table in section 3, the disagreement is informative
and should not be patched away.  The likeliest causes, in order:
  * File 1 reporting "is false" (accept reachable): check that DRN_u really uses
    ring_v and not Om_v -- that single term is the whole theorem.
  * Files 6/7 failing to terminate or reporting "cannot be proved": the
    equational theory may not have completed; try removing the pscal equation
    and hard-coding c as a free name to confirm the rest of the model.
  * Files 3/4 reporting phase-0 FALSE: the ephemeral reveal is reaching the
    adversary earlier than intended; check that only omega_u is on h_leak.

--------------------------------------------------------------------------------
 7. PRIVATE CHANNELS ARE AN INCOMPLETENESS HAZARD (learned the hard way)
--------------------------------------------------------------------------------
Enforcing a matched session with a private channel cost us two rounds of
debugging, and the lesson generalises.

  Round 1 (single channel c_uv).  Both roles read and wrote the same channel,
  so ProVerif delivered one initiator's Psi_1 into another INITIATOR's Psi_2
  input.  The derivation contained hexp(hexp(h_g,omega_u_1),omega_u_2) -- two
  initiator ephemerals, no omega_v.  Fixed by splitting into c_u2v / c_v2u.

  Round 2 (directed channels).  The self-pairing was gone, but the derivation
  now spliced u-session TWO's request to u-session ONE's reply.  ProVerif
  abstracts a private channel as a message POOL: mess(c,...) records that a
  term may appear on the channel, not which session consumes it, nor that an
  output is consumed once.  The abstraction is SOUND but INCOMPLETE, so it
  reports "cannot be proved" -- neither a proof nor an attack.

  Resolution.  For a session-key query there is no need for channels at all.
  The eCK Test query concerns ONE designated session, so File 3 v2 draws both
  parties' ephemerals in a SINGLE process, publishes the whole transcript, and
  applies the reveals.  Matching holds by construction and the query is
  decided.  This is not a weakening: the adversary still sees the full
  transcript, holds the certificate scalars, and gets both reveals.

  Why Files 4, 5 and 9 were NOT rewritten.  They returned DEFINITE verdicts.
  ProVerif's "true" is sound (its abstraction over-approximates the real
  traces), and its "false" came with an executable trace.  A definite verdict
  obtained through an incomplete abstraction is still a valid verdict; only
  "cannot be proved" signals that the abstraction got in the way.

  General guidance.  Use a private channel only when unbounded matched sessions
  are genuinely needed.  For secrecy of a single test session, hard-wire the
  session instead -- it is both more faithful to the eCK Test query and far
  friendlier to the solver.
================================================================================
