function safeUrl(value) {
  try {
    const url = new URL(String(value));
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : '#';
  } catch {
    return '#';
  }
}

// Shared helpers for reading data/news.json, written by scripts/fetch_news.py
// (run on a schedule by .github/workflows/fetch-news.yml)

const NEWS_JSON_PATH = 'data/news.json';

async function loadNewsData() {
  const res = await fetch(`${NEWS_JSON_PATH}?_=${Date.now()}`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`Failed to load news data (${res.status})`);
  return res.json();
}

function timeAgo(isoString) {
  if (!isoString) return '';
  const then = new Date(isoString).getTime();
  if (Number.isNaN(then)) return '';
  const diffMs = Date.now() - then;
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(isoString).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str ?? '';
  return div.innerHTML;
}
