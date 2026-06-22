# SOC AI Agent - Enterprise Integrations

This build wires three enterprise security integrations into the SOC flow:

- Elasticsearch for alert / incident / report / asset indexing and search
- VirusTotal for IOC enrichment
- CrowdStrike Falcon for response containment

## Services

- SIEM Engine: `:8001`
- TIP Platform: `:8002`
- AI Orchestrator: `:8003`
- Response Engine: `:8004`
- Dashboard: `:8080`
- Elasticsearch: `:9200`

## Env vars

- `VIRUSTOTAL_API_KEY`
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `CROWDSTRIKE_BASE_URL`
- `CROWDSTRIKE_CLIENT_ID`
- `CROWDSTRIKE_CLIENT_SECRET`

## What changed

- SIEM indexes alerts and assets into Elasticsearch and provides `/search/alerts`
- TIP enriches IPs, domains, hashes, and URLs through VirusTotal when configured
- Response engine uses a CrowdStrike Falcon connector for `isolate_host` / `restore_host`
- AI Orchestrator indexes incidents and reports into Elasticsearch and provides search endpoints

## Run

```bash
docker compose up --build
```
