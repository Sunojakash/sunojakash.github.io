document.addEventListener('DOMContentLoaded', async () => {
  const list = document.getElementById('teaser-list');
  if (!list) return;
  try {
    const data = await loadNewsData();
    const articles = (data.articles || []).slice(0, 3);
    if (!articles.length) {
      list.innerHTML = '<p class="state-msg">No articles yet — the feed populates after the first automated run.</p>';
      return;
    }
    list.innerHTML = articles.map(a => `
      <div class="article-card">
        <div class="article-meta">
          <span class="article-source">${escapeHtml(a.source)}</span>
          <span>${timeAgo(a.published)}</span>
        </div>
        <h3><a href="${escapeHtml(safeUrl(a.link))}" target="_blank" rel="noopener">${escapeHtml(a.title)}</a></h3>
      </div>
    `).join('');
  } catch (err) {
    list.innerHTML = '<p class="state-msg error">Could not load the news feed right now. It refreshes automatically every few hours.</p>';
    console.error(err);
  }
});
