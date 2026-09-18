# cybercircuit.ai

Static site for Cyber-Circuit — Evidence-Bounded Change Assurance for Cloud Security.
A product of Quantum Clarity LLC.

Plain HTML + CSS. No build step, no framework, no dependencies.
Deploy anywhere that serves static files (currently: Cloudflare Pages).

## Pages

- `index.html` — Home (ported from the finished Squarespace Code Block, 5 sections)
- `about.html` — About (ported from the finished Squarespace Code Block, 4 sections)
- `browser.html` — Cyber-Circuit Browser product page (copy ported from
  cyber-circuit.com/cyber-circuit-browser; download buttons point at the real
  GitHub release assets under `amitb-quantum/cyber-circuit-browser` v1.0.0)
- `contact.html` — Contact (`info@quantum-clarity.com`)
- `styles.css` — all site styles, namespaced per page (`.cc-home`, `.cc-about`,
  `.cc-browser`, `.cc-contact`) plus shared header/footer chrome

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
- Services is intentionally out of the navigation: the Squarespace services
  page is empty, and the product has one focused offering
  (Evidence-Bounded Change Assurance) with "Request an evaluation" as the CTA.
  Final structure: Home, About, Browser, Contact.
