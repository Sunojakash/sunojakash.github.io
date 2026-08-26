let allArticles = [];
let activeSource = 'All';

document.addEventListener('DOMContentLoaded', init);

async function init() {
  const syncRow = document.getElementById('sync-row');
  const filterBar = document.getElementById('filter-bar');
  const list = document.getElementById('article-list');

  try {
    const data = await loadNewsData();
    allArticles = data.articles || [];

    if (syncRow) {
      const stamp = data.last_updated ? timeAgo(data.last_updated) : 'unknown';
      syncRow.innerHTML = `<span class="dot"></span> Last synced ${stamp} · ${allArticles.length} articles tracked`;
    }

    const sources = ['All', ...new Set(allArticles.map(a => a.source).filter(Boolean))];
    if (filterBar) {
      filterBar.innerHTML = sources.map(s =>
        `<button class="chip${s === 'All' ? ' active' : ''}" data-source="${escapeHtml(s)}">${escapeHtml(s)}</button>`
      ).join('');
      filterBar.addEventListener('click', (e) => {
        const btn = e.target.closest('.chip');
        if (!btn) return;
        activeSource = btn.dataset.source;
        filterBar.querySelectorAll('.chip').forEach(c => c.classList.toggle('active', c === btn));
        render();
      });
    }

    render();
  } catch (err) {
    console.error(err);
    if (list) {
      list.innerHTML = '<p class="state-msg error">Couldn\u2019t load the news feed. Check back shortly \u2014 it refreshes automatically every few hours.</p>';
    }
    if (syncRow) syncRow.innerHTML = '<span class="dot" style="background:var(--accent-signal)"></span> Feed unavailable';
  }
}

function render() {
  const list = document.getElementById('article-list');
  if (!list) return;

  const items = activeSource === 'All'
    ? allArticles
    : allArticles.filter(a => a.source === activeSource);

  if (!items.length) {
    list.innerHTML = '<p class="state-msg">No articles yet for this source. The feed populates after the next automated run.</p>';
    return;
  }

  list.innerHTML = items.map(a => `
    <article class="article-card">
      <div class="article-meta">
        <span class="article-source">${escapeHtml(a.source)}</span>
        <span>${timeAgo(a.published)}</span>
      </div>
      <h3><a href="${escapeHtml(a.link)}" target="_blank" rel="noopener">${escapeHtml(a.title)}</a></h3>
      ${a.summary ? `<p>${escapeHtml(a.summary)}</p>` : ''}
      <a class="article-link" href="${escapeHtml(a.link)}" target="_blank" rel="noopener">Read on ${escapeHtml(a.source)} →</a>
    </article>
  `).join('');
}
