# Akash Sunoj — Portfolio + Live Threat Intel Feed

A static profile site with a cybersecurity news page that updates itself.
No backend server, no database, no build step.

```
index.html          Profile / resume homepage (also shows top 3 headlines)
news.html            Full news feed page, with source filters
styles.css            Shared "operations console" design system
script.js             Nav menu + footer year
news-data.js          Shared fetch/format helpers for the news pages
news.js / news-teaser.js   Page-specific rendering
data/news.json        The data the site reads (written by the bot, see below)
scripts/fetch_news.py       Pulls RSS feeds and rewrites data/news.json
.github/workflows/fetch-news.yml   Runs the script on a schedule via GitHub Actions
requirements.txt       Python deps for the fetch script
```

## How the automation works

1. `.github/workflows/fetch-news.yml` runs on a schedule (default: every 4
   hours, `0 */4 * * *`) and can also be triggered manually from the
   **Actions** tab (`Run workflow`).
2. It runs `scripts/fetch_news.py`, which pulls each feed in the `FEEDS`
   list, strips HTML from summaries, and de-duplicates against whatever's
   already in `data/news.json` (so re-runs never create duplicate entries).
3. It merges, sorts newest-first, keeps the latest 150 articles, and writes
   `data/news.json`.
4. The workflow commits and pushes that file straight to `main` if it
   changed.
5. `news.html` / `index.html` fetch `data/news.json` client-side on page
   load — there's nothing to rebuild, so the update is live the moment the
   commit lands and your host re-serves the file.

Curated feeds (edit the `FEEDS` list in `scripts/fetch_news.py` to add or
remove sources): The Hacker News, Krebs on Security, Dark Reading,
SecurityWeek, The Record, CISA Cybersecurity Advisories, SANS Internet
Storm Center.

**One caveat:** BleepingComputer's feed blocks requests from cloud/CI IP
ranges (confirmed 403 to GitHub Actions runners as of testing), even
though it works fine from a home network. It's in the feed list but
disabled by default — flip `enabled` to `True` next to it only if you're
running the script somewhere with a residential IP (e.g. a self-hosted
runner), otherwise it'll just log a warning every run and add nothing.

## Preview locally

No build step — just serve the folder:

```bash
python -m http.server 8000
# then open http://localhost:8000
```

Run the fetcher once to populate real data before previewing:

```bash
pip install -r requirements.txt
python scripts/fetch_news.py
```

## Deploying

**Option A — GitHub Pages (simplest, no extra account needed)**
1. Push this repo to GitHub.
2. Repo Settings → Pages → Source: "Deploy from a branch" → `main` / `/ (root)`.
3. Done. Every push to `main` — including the bot's automated commits —
   updates the live site within a minute or two.
4. Make sure the fetch-news workflow has permission to push: Settings →
   Actions → General → Workflow permissions → "Read and write permissions"
   (the workflow file already requests `contents: write`, but repos
   sometimes default this to read-only).

**Option B — Azure Static Web Apps (fits your Azure background)**
1. In the Azure Portal, create a Static Web App and connect it to this
   GitHub repo (build preset: "Custom", app location `/`, no output
   location needed — it's already static).
2. Azure adds its own deploy workflow to `.github/workflows/` automatically.
   Leave `fetch-news.yml` as-is; the two workflows run independently and
   won't conflict.
3. Every push to `main` (including the bot's commits) triggers Azure's
   deploy workflow and republishes automatically.

## Customizing

- **Contact links**: the footer and hero have placeholder `#` links for
  LinkedIn/GitHub — swap in your real URLs.
- **Photo**: the hero currently uses an animated Zero Trust rings graphic
  instead of a headshot. Swap in a photo by replacing the `.rings` block
  in `index.html` with an `<img>` if you'd rather show your face.
- **Refresh interval**: change the cron line in
  `.github/workflows/fetch-news.yml` (cron is UTC).
- **Article cap / summary length**: `MAX_ARTICLES` and `SUMMARY_MAX_CHARS`
  at the top of `scripts/fetch_news.py`.

## A privacy note

Your resume includes a home address and phone number — those were left
out of the public site on purpose (a resume you send to a specific
employer and a page indexed by search engines are different audiences).
Your email is included as a `mailto:` link since that's the normal way to
invite contact from a portfolio site. Add other contact channels as you
see fit.
