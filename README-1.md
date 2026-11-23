# AI & Cybersecurity Intelligence Collector — v1.0

This is the collection-only MVP. It does not call Azure AI Foundry yet.

## Files
- `ai_cyber_intelligence.py` — consolidated collection, triage, and reporting script
- `requirements.txt` — Python dependencies
- `azure-pipelines.yml` — weekly Azure DevOps pipeline

## Local run
```bash
python -m pip install -r requirements.txt
python ai_cyber_intelligence.py
```

Outputs are written to `reports/`:
- Collection summary in Markdown
- Findings in CSV
- Findings in JSON

## Optional environment variables
- `DAYS_BACK` (default 7)
- `GITHUB_TOKEN` (optional; use a read-only token for public repositories)
- `OUTPUT_DIR` (default `reports`)
- `MAX_GOOGLE_ITEMS_PER_QUERY` (default 30)
- `MAX_HF_MODELS_PER_ORG` (default 15)

## Azure DevOps setup
1. Commit the three project files to your repository.
2. Add a secret pipeline variable named `GITHUB_TOKEN` if you want authenticated GitHub API access. It is optional.
3. Ensure the pipeline YAML is on the `main` branch, or change the schedule branch in the YAML.
4. Run the pipeline manually once to validate network access and artifact publishing.

The scheduled cron is 15:00 UTC Sunday. Azure DevOps cron schedules are UTC; this corresponds to 8:00 AM Mountain Standard Time / 9:00 AM Mountain Daylight Time.

## Important limitations
- Google News RSS is a discovery channel, not a guaranteed complete archive or official API.
- Public RSS/search availability and upstream rate limits can change.
- Hugging Face `lastModified` means model metadata/repository activity changed; it does not prove a new model release or a security-relevant change.
- The initial collector does not retain a database between runs. Historical week-over-week change detection is deferred.
- Preliminary relevance scores are keyword-based and are not threat severity ratings.
- Source content is treated as untrusted data. The script does not execute downloaded content.
- Researcher names "Nathan" and "Hamiel" are unresolved and intentionally excluded from individual-name searches until more identifying information is provided.
