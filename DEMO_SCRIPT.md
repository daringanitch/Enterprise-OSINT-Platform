# Enterprise OSINT Platform — Demo Script
## "Operation SHATTERED PANE" (~10 minutes)

> **Audience**: Security leadership, SOC teams, threat intelligence buyers, investors
> **Tone**: You're walking through a real investigation, not a feature checklist
> **Goal**: By the end, the audience understands that this platform does in 10 minutes what a skilled analyst would take 4–8 hours to do manually — and produces audit-quality output

---

## Pre-Demo Setup (5 minutes before)

```bash
# 1. Seed the demo data
cd Enterprise-OSINT-Platform/simple-backend
APP_DATA_DIR=/tmp/osint_demo python demo_scenario.py --reset

# 2. Start the backend
APP_DATA_DIR=/tmp/osint_demo python app.py &

# 3. Start the frontend (or use kubectl port-forward if on Kubernetes)
cd ../frontend && npm start

# 4. Log in at http://localhost:3000
#    Username: admin   Password: admin123
```

**Browser prep**: Open the platform, log in, and navigate to the Dashboard. Have the investigation list ready. Close other tabs.

---

## The Opening Line

> *"Our SOC received a phishing alert 48 hours ago — a DocuSign impersonation email targeting three finance-department employees. None of them clicked. Normally that's where it ends. Let me show you what happens when you don't stop there."*

---

## Scene 1 — Dashboard (30 seconds)

**Navigate to**: Dashboard

**What to say**:
> *"This is the command view. We have one high-priority investigation running — Operation SHATTERED PANE — alongside our continuous monitoring watchlists. The risk score is 87 out of 100. Let's see why."*

**Point to**: The risk score card, the active alert count (3), the investigation status.

**Pause on**: Nothing. Keep moving — the Dashboard is just context-setting.

---

## Scene 2 — Investigation Overview (90 seconds)

**Navigate to**: Investigations → click "Operation SHATTERED PANE"

**What to say**:
> *"We started with one domain: secure-docview-portal.net. A single phishing domain. In the time it takes to make a cup of coffee, the platform ran seven intelligence sources in parallel — WHOIS, DNS, SSL certificate transparency logs, VirusTotal, AbuseIPDB, Shodan, and passive DNS. Here's what it found."*

**Scroll through** the investigation overview. Pause briefly on:

- **7 related domains** in the infrastructure list — say: *"The platform didn't just look at the one domain we gave it. The SSL certificate had four Subject Alternative Names. Four phishing domains on a single certificate. That's the first pivot."*

- **The C2 IP card** (185.220.101.47) — say: *"The IP behind these domains had 47 abuse reports in 30 days and was flagged by 8 of 85 antivirus engines. Shodan showed an Apache Tomcat listener on port 8080 — that's the default CobaltStrike Beacon listener profile."*

- **Key findings list** — read the first finding aloud: *"Single SSL certificate SAN field links 4 phishing domains to one operator — the pivot that revealed the full infrastructure cluster."*

**The line that lands**: *"We went from one domain to a seven-domain phishing cluster run by a financially-motivated threat actor — all automatically, before an analyst had even opened a browser tab."*

---

## Scene 3 — Graph Intelligence (2 minutes)

**Navigate to**: Graph Intelligence tab (within the investigation, or via sidebar)

**What to say**:
> *"This is where it gets interesting. Most platforms give you a table of indicators. We give you a relationship map."*

**What the audience sees**: A graph with the primary domain at center, 6 sibling domains and the C2 IP connected by edges labeled with relationship types (RESOLVES_TO, SHARES_CERTIFICATE, SHARES_REGISTRANT, HOSTS).

**Interact with**:
- Click on the **central domain node** — show the entity detail panel
- Point to the **certificate node** in the middle: *"This is the SSL certificate. It's the connective tissue of the whole cluster. Without pivoting through certificate transparency logs, you'd never know these seven domains were operated by the same person."*
- Click **"Run Blast Radius Analysis"** — show the resulting panel: *"If the C2 server is seized or sinkholed, this shows the impact radius. We can see which domains lose their C2 access and estimate how many victim machines that affects."*

**The line that lands**: *"A human analyst building this graph manually — cross-referencing WHOIS records, cert logs, passive DNS — would take four to six hours. The platform did it in under three minutes."*

---

## Scene 4 — Monitoring & Alerts (60 seconds)

**Navigate to**: Monitoring (sidebar)

**What to say**:
> *"We didn't just investigate and move on. We put this infrastructure on a watchlist. The platform checks it continuously — DNS changes, new certificate issuances, IP reputation shifts."*

**Show the 3 alerts**:

1. **New certificate issued** (HIGH) — *"While we were writing the report, the operator issued a new certificate. We caught it in real time."*
2. **IP reputation jump +31 points** (CRITICAL) — *"The C2 IP went from a score of 51 to 82 overnight. 25 new abuse reports in 24 hours — the operator is actively running campaigns."*
3. **New subdomain: mail.secure-docview-portal.net** (MEDIUM) — *"A mail subdomain appeared. The operator is activating their phishing delivery infrastructure. This is an active, ongoing campaign, not a historical artifact."*

**The line that lands**: *"Without continuous monitoring, you do an investigation, write a report, and the threat evolves while the report sits in a JIRA ticket. This platform keeps watching."*

---

## Scene 5 — Analytic Tradecraft (2 minutes)

**Navigate to**: Analytic Workbench (sidebar) → select the SHATTERED PANE investigation

**What to say**:
> *"Here's where we differ from every other OSINT tool on the market. Every other platform tells you what the data says. We make you prove you've thought carefully about what it means — and document that you considered alternatives."*

**Tab 1 — Intel Items**: Show the list of 8 intelligence items, each with Admiralty ratings.
> *"Every piece of evidence is rated on the NATO Admiralty scale — source reliability from A to F, information credibility from 1 to 6. This isn't a flat list of IOCs. It's structured intelligence with provenance."*

**Tab 2 — Hypotheses**: Show the three hypotheses (Cobalt Group, FIN7, Independent Actor).
> *"Before we committed to attribution, we wrote down three competing explanations. We didn't lead with a conclusion."*

**Tab 3 — ACH Matrix**: Show the 24-cell Analysis of Competing Hypotheses matrix.
> *"This is Analysis of Competing Hypotheses — the gold standard analytic technique from the Intelligence Community. Each piece of evidence is scored against each hypothesis: consistent, inconsistent, or not applicable. The hypothesis with the fewest inconsistencies wins — not the one that feels right."*

**Point to key cells**:
- MITRE TTP row: *"The HK multi-hop relay pattern — that row of inconsistencies against FIN7 is what drove us toward Cobalt Group."*
- Credential exposure row: *"The OPSEC failure — compromised registrant email — is consistent with an independent actor, which introduces uncertainty. That's why our confidence is moderate-high rather than high."*

**Tab 4 — Conclusions**: Show the IC-standard conclusion.
> *"The output isn't a paragraph of opinions. It's structured with IC confidence language, key assumptions stated explicitly, caveats documented, and — this is important — a devil's advocate challenge that tried to argue we were wrong, and the lead analyst's response to that challenge."*

**The line that lands**: *"If your analyst can't show their reasoning in a format that would survive peer review, you don't have intelligence — you have a guess with a logo on it."*

---

## Scene 6 — Credential Intelligence (30 seconds)

**Navigate to**: Credential Intelligence (sidebar) → search for `admin@mailfast.pro`

**What to say**:
> *"Here's the detail that made this investigation interesting. The operator who registered these phishing domains used an email address that was already in a breach database — stolen by RedLine Stealer on their own machine. The attacker got compromised."*

**Show the result**: Hudson Rock Cavalier hit, plaintext credential, risk score 94.

> *"This is why we integrate credential intelligence alongside infrastructure analysis. OPSEC failures like this are attribution gold — and they're findable automatically."*

---

## Scene 7 — Export (30 seconds)

**Navigate to**: Investigation detail → Export options (or Reports)

**What to say**:
> *"When you're done, you can export in two formats. For your SOC and EDR team — a STIX 2.1 bundle with all IOCs, relationships, and MITRE mappings in a machine-readable format you can push directly to your threat intel platform or MISP instance. For your CISO or board — a PDF executive report with the key findings, risk score, and recommendations."*

**Show both options** (click Generate PDF, show STIX export button).

> *"Both are generated from the same underlying investigation data. One report, two audiences, one click each."*

---

## Closing Line

> *"What you just saw: a phishing domain turned into a fully-attributed, 7-domain threat actor infrastructure cluster with an ACH matrix, continuous monitoring, and exportable intelligence — in under 10 minutes. That's what a skilled analyst does in a full day, with documentation that usually takes another day to write. This is the platform that closes that gap."*

---

## Handling Tough Questions

**"Is this data live or pre-loaded for the demo?"**
> *"The demo uses pre-seeded data so we can show a complete investigation without waiting for real API calls. In production, every data point is fetched live from the actual sources — cert transparency logs, VirusTotal, Shodan, AbuseIPDB, passive DNS. The same investigation on a real target would run in about the same time."*

**"We already have ThreatConnect / MISP / OpenCTI. Why this?"**
> *"Those are great threat intel platforms for storing and sharing indicators. This platform is for generating the intelligence in the first place — the investigation workflow, the pivot analysis, the ACH attribution work. The two are complementary; this platform exports directly to MISP and generates STIX bundles your existing platforms can ingest."*

**"What about false positives?"**
> *"The Admiralty ratings and ACH matrix exist specifically to address this. Low-reliability sources are rated accordingly. Evidence that doesn't hold up under scrutiny scores as inconsistent in the ACH matrix and pulls down the confidence level. The system doesn't make attribution claims — it surfaces evidence and lets the analyst make structured, documented judgments."*

**"Is this open source?"**
> *"The core platform is available for individual use. Commercial deployment — in a commercial SOC, a paid service, or embedded in a product — requires a licensing arrangement. The source is available for review and contribution."*

---

## What Not To Do

- **Don't demo feature-by-feature** ("and here's the settings page, and here's the admin panel"). Tell the investigation story; features emerge naturally.
- **Don't apologize for anything**. If a page is slow or a tab is empty, say "in the full deployment this would show X" and keep moving.
- **Don't read the screen**. The audience can read. Talk about what it means.
- **Don't end on the graph**. The graph is visually impressive but the tradecraft scene is the intellectual differentiator. End on the conclusion or the export — those are the things that make buyers write checks.

---

## 3-Minute Version (Executive Elevator)

Skip Scenes 4, 5, and 6. Navigate directly 1 → 2 → 3 → 7.

Opening: *"One phishing domain, 3 minutes, seven related domains, full attribution, exportable STIX bundle."*

Spend 90 seconds on the graph (most visual impact), 30 seconds on the investigation overview, 30 seconds on the export options. Close with the line about analyst-hours vs. platform-minutes.
