# cybercircuit.ai

Static site for Cyber-Circuit: a circuit breaker for AI agents.
A product of Quantum Clarity LLC.

Plain HTML + CSS. No build step, no framework, no dependencies.
Deploy anywhere that serves static files (currently: Cloudflare Pages).

## Pages

- `index.html`: Home. Cyber-Circuit as a circuit breaker for AI agents, built on the
  CircuitBreaker engine (`amitb-quantum/circuit-breaker`, private preview). Every
  claim in "What's proven" must map to a test that passes on the lab machine, or be
  marked In progress or Planned. Update that table when a phase passes.
- `research.html`: Earlier work. The AWS IAM evidence-bounded change assurance page
  (formerly the home page), with a note that it is not the current product.
- `browser.html`: Cyber-Circuit Browser product page (copy ported from
  cyber-circuit.com/cyber-circuit-browser; download buttons point at the real
  GitHub release assets under `amitb-quantum/cyber-circuit-browser` v1.0.0)
- `get.html`: Get access. Builds go to design partners on request (no public download). Carries the release-key fingerprint, one of the two places it is published (the other is the `amitb-quantum/cybercircuit` README); keep them identical.
- `about.html`: About
- `contact.html`: Contact (`info@quantum-clarity.com`)
- `styles.css`: all site styles, namespaced per page (`.cc-agent` for home,
  `.cc-home` for research, `.cc-about`, `.cc-browser`, `.cc-contact`) plus shared
  header and footer chrome

## Local preview

```bash
cd cybercircuit.ai
python3 -m http.server 8000
# open http://localhost:8000
```

## Deploy to Cloudflare Pages

1. Push this directory to a GitHub repo.
2. Cloudflare dashboard → Workers & Pages → Create → Pages → Connect to Git.
3. Select the repo. Build settings: **no build command**, output directory `/`
   (or the repo root).
4. After the first deploy: Pages project → Custom domains → Set up a custom
   domain → `cybercircuit.ai` (and optionally `www.cybercircuit.ai`).
   DNS is already on Cloudflare (domain registered via Cloudflare Registrar),
   so the records are created automatically. HTTPS is automatic.
5. Optional: Email Routing (free) for `info@cybercircuit.ai`.

## Notes

- Contact email stays `info@quantum-clarity.com` per owner decision.
- The Squarespace site at cyber-circuit.com stays live and untouched during
  the build; the cutover decision comes later.
- Navigation: Home, Research, Browser, About, Contact. The call to action is
  "Request early access".
