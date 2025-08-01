How we get EPSS scores:
----------------------------------


**https://orca.security/resources/blog/epss-scoring-system-explained/**
**https://orca.security/resources/blog/cvss-version-4-versus-version-3/**

* CVE IDs (from scanner or asset inventory).
* Call the FIRST.org EPSS REST API (/data/v1/epss?cve=<list>&date=<today>)
* Parse the JSON response for each CVE’s epss_score and percentile.
* Store/cache results (e.g. in PostgreSQL or Redis) and deploye it in own API dashboard.

-> Fetch & Scheduler: Fetch & Scheduler: Python (requests + cron) or Node.js (axios + node-cron)
-> Service: Flask/FastAPI, Express, or Spring Boot
-> Storage: PostgreSQL/MySQL for history; Redis for fast lookups
-> Orchestration: Docker + Kubernetes CronJob (or cloud functions + scheduler)
-> UI: React (with Recharts/Chart.js) or Grafana dashboards

* Notes for Calcultation : 
----------------------------

1. Gathering Exploitation Signals : 
   
  - > Every day, the system ingests the latest observations of real‑world exploit activity from multiple feeds:
* **Honeypots** deployed by security researchers, which capture attempted attacks and map them back to CVE IDs.
* **Partner telemetry** from security vendors and incident‑response firms, sharing anonymized logs of exploits they’ve seen.
* **CISA’s KEV catalog**, which lists vulnerabilities known to be exploited in the wild—the “Known Exploited Vulnerabilities.”
* **Public advisories and reports** (e.g. mailing lists, CERT bulletins) that explicitly link CVEs to active campaigns.
  
  ***NOTE***
Together, these sources give us a binary label for each CVE on each day: “observed exploited” vs. “not observed.”


1. Building the Feature Set
- > For each CVE, we assemble a rich profile of static and dynamic attributes:

* **Vendor & product metadata:** who makes the software, how many products are affected (CPE counts).
* **Age:** days since the CVE was published.
* **CVSS metrics:** base score and individual metrics (attack vector, attack complexity, privileges required, user interaction, and impact sub‑scores).
* **CWE categories:** the Common Weakness Enumeration identifiers that characterize the type of vulnerability.
* **Reference counts:** how many advisories, patches, exploits, and external URLs mention the CVE.
* **Textual indicators:** length and content of the vulnerability description, presence of high‑risk keywords (e.g. “remote code execution,” “buffer overflow”).
  
3. Training the Machine‑Learning Model
   
* We take a historical window (e.g. the last 6–12 months) of daily exploit labels and their corresponding feature vectors.
* A supervised learning algorithm—typically a gradient‑boosted decision‑tree model or logistic‑regression ensemble—is trained to predict the probability that a CVE, given its features on day D, will be seen exploited in the following 30 days.
* The training objective minimizes a probability‑calibration loss (log‑loss), so the output scores can be interpreted directly as 0–1 probabilities.

4. Validation & Calibration
   
* We hold out a portion of data to test how well the model’s probabilities align with actual exploitation rates (e.g. via AUC‑ROC and reliability diagrams).
* If necessary, we calibrate (e.g. via Platt scaling or isotonic regression) so that, for example, “0.2 probability” truly corresponds to ~20 % of those CVEs being exploited within 30 days.
5. Daily Scoring Pipeline
   
5. Each morning:
   
* **Refresh** the CVE feature database (new CVEs, updated CVSS or references).
* **Recompute** every CVE’s feature vector.
* **Score** them through the trained model, producing a fresh EPSS probability for each.
* **Rank** those probabilities into percentiles so you can quickly see, say, “the top 5 % most‑likely‑to‑be‑exploited vulnerabilities.”



***How the Scores Are Calculated***

1. Each day, we collect two things:
   
* A list of which vulnerabilities were actually attacked yesterday.
* Detailed information about every vulnerability (who makes the software, how old the flaw is, its official CVE identifier, its CVSS severity ratings, its CWE category, and so on).
2. We feed both sets of data into a machine‑learning model. The model “learns” which kinds of flaws tend to get exploited, and then it uses that knowledge to predict how likely each vulnerability is to be attacked in the next 30 days.
3. Our records of real attacks come from multiple places:
* **Honeypots** that tempt attackers into revealing their methods.
* **Company and partner reports** of exploits they’ve seen.
* **CISA’s KEV catalog** of known exploited vulnerabilities.
  
  - > NOTE : 
Putting it all together, the model looks at past attack patterns plus detailed vulnerability facts and spits out a score between 0 and 1 that reflects the chance of exploitation.




--------------------------------------------------

## databases with :
1) prioritization- relevant metadata 
2) daily report //
3) CVE identifier

# Steps : 

1. Data sources  
2. Enrichment & scoring
3. Forecasting model
4. Delivery & updates

# metadata:-
---------------------------------
* NVD API for CVE metadata (CVSS, publish date, references) # https://nvd.nist.gov/developers 
* EPSS CSV (daily scores per CVE) - 
* Exploit indicators (Exploit-DB, CISA KEV)
* 
  . Joins CVE → CVSS, publication date, exploit tags
    Flags PoCs, active exploit status, KEV inclusion
    scoring : 
    ---------------------
  . Normalized schema: (cve_id, date, cvss, epss, exploit_flags )

# CVE identifier :
------------------
-> CVE Definitions from MITRE { MITRE operates the primary CVE List, where all new vulnerability identifiers (CVE‑YYYY‑NNNN) are first published.}

-> Ingestion into NVD 
-> NVD pull the data ( SDLC ) the latest CVE record from MITRE time/day .
-> CVSS Scoring: Trained analysts (and sometimes the CNA itself) assign a CVSS v3.1 Base Score and vector string based on the vulnerability’s technical details.

-> Vulnerability Type: Tags like “Denial of Service,” “Remote Code Execution,” etc., are added.

https://nvd.nist.gov

# Delivery & Reporting:
----------------------------

Report Generator

Pulls enriched metadata + forecast
Renders terminal tables and CVEdetails‑style charts

Channels

Email/Slack at 9 AM local (“Daily EPSS CVE Report”)
Optionally, dashboard embed


