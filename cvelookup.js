let allFindings = [];
let activeView = 'all';

document.addEventListener('DOMContentLoaded', initCves);

async function initCves() {
  try {
    const response = await fetch('data/cves.json', { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    allFindings = data.findings || [];

    const updated = data.last_updated ? timeAgo(data.last_updated) : 'unknown';
    document.getElementById('sync-row').innerHTML =
      `<span class="dot"></span> Last synced ${escapeHtml(updated)} · ${allFindings.length} findings tracked`;

    renderMetrics(data);
    populateAssets();
    bindFilters();
    render();
  } catch (err) {
    console.error(err);
    document.getElementById('sync-row').innerHTML =
      '<span class="dot" style="background:#ef4444"></span> Vulnerability feed unavailable';
    document.getElementById('cve-body').innerHTML =
      '<tr><td colspan="7" class="empty">No generated CVE data found yet. Add assets to <code>data/assets.json</code> and run the CVE sync workflow.</td></tr>';
  }
}

function renderMetrics(data) {
  const assets = data.asset_count ?? new Set(allFindings.map(x => x.asset_id)).size;
  const vulnerable = data.vulnerable_asset_count ?? assets;
  const critical = allFindings.filter(x => x.severity === 'CRITICAL').length;
  const kev = allFindings.filter(x => x.known_exploited).length;

  document.getElementById('metric-assets').textContent = assets;
  document.getElementById('metric-vulnerable').textContent = vulnerable;
  document.getElementById('metric-critical').textContent = critical;
  document.getElementById('metric-kev').textContent = kev;
}

function populateAssets() {
  const select = document.getElementById('assetFilter');
  const assets = [...new Set(allFindings.map(x => x.asset_name).filter(Boolean))].sort();
  select.innerHTML = '<option value="All">All assets</option>' +
    assets.map(a => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`).join('');
}

function bindFilters() {
  ['search','severity','exploit','assetFilter'].forEach(id => {
    document.getElementById(id).addEventListener(id === 'search' ? 'input' : 'change', render);
  });

  document.getElementById('chips').addEventListener('click', e => {
    const button = e.target.closest('.chip');
    if (!button) return;
    activeView = button.dataset.view;
    document.querySelectorAll('.chip').forEach(x => x.classList.toggle('active', x === button));
    render();
  });

  document.getElementById('detail-close').addEventListener('click', closeDetail);
  document.getElementById('detail').addEventListener('click', e => {
    if (e.target.id === 'detail') closeDetail();
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeDetail();
  });
}

function render() {
  const query = document.getElementById('search').value.trim().toLowerCase();
  const severity = document.getElementById('severity').value;
  const exploit = document.getElementById('exploit').value;
  const asset = document.getElementById('assetFilter').value;

  let items = allFindings.filter(x => {
    const haystack = [
      x.cve_id, x.asset_id, x.asset_name, x.vendor, x.product,
      x.version, x.remediation, x.description
    ].join(' ').toLowerCase();

    if (query && !haystack.includes(query)) return false;
    if (severity !== 'All' && x.severity !== severity) return false;
    if (exploit === 'KEV' && !x.known_exploited) return false;
    if (exploit === 'NOT_KEV' && x.known_exploited) return false;
    if (asset !== 'All' && x.asset_name !== asset) return false;

    if (activeView === 'priority' && !(x.known_exploited || x.severity === 'CRITICAL' || (x.epss || 0) >= 0.5)) return false;
    if (activeView === 'patch' && !x.fixed_version) return false;
    if (activeView === 'kev' && !x.known_exploited) return false;

    return true;
  });

  items.sort((a,b) => priorityScore(b) - priorityScore(a));

  const body = document.getElementById('cve-body');
  if (!items.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No findings match the current filters.</td></tr>';
    return;
  }

  body.innerHTML = items.map((x, i) => `
    <tr data-index="${i}" class="finding-row" style="cursor:pointer">
      <td>
        <div class="asset-name">${escapeHtml(x.asset_name || x.asset_id || 'Unknown asset')}</div>
        <div class="muted">${escapeHtml(x.environment || '')}</div>
      </td>
      <td>
        <div>${escapeHtml(x.vendor || '')} ${escapeHtml(x.product || '')}</div>
        <div class="muted mono">${escapeHtml(x.version || 'version unknown')}</div>
      </td>
      <td><span class="cve-link">${escapeHtml(x.cve_id)}</span></td>
      <td>
        <span class="badge ${severityClass(x.severity)}">${escapeHtml(x.severity || 'UNKNOWN')}</span>
        <div class="mono" style="margin-top:5px">${x.cvss != null ? Number(x.cvss).toFixed(1) : '—'}</div>
      </td>
      <td><span class="badge ${x.known_exploited ? 'kev' : 'not-kev'}">${x.known_exploited ? 'KEV' : 'No KEV'}</span></td>
      <td class="mono">${x.epss != null ? (Number(x.epss) * 100).toFixed(1) + '%' : '—'}</td>
      <td>
        ${x.fixed_version ? `<span class="badge patch">Fix: ${escapeHtml(x.fixed_version)}</span>` : '<span class="badge no-patch">No fixed version</span>'}
      </td>
    </tr>
  `).join('');

  [...body.querySelectorAll('.finding-row')].forEach((row, i) => {
    row.addEventListener('click', () => openDetail(items[i]));
  });
}

function openDetail(x) {
  document.getElementById('detail-title').textContent = x.cve_id;
  document.getElementById('detail-grid').innerHTML = [
    ['Asset', x.asset_name || x.asset_id],
    ['Product', `${x.vendor || ''} ${x.product || ''}`],
    ['Installed version', x.version || 'Unknown'],
    ['CVSS', x.cvss != null ? `${Number(x.cvss).toFixed(1)} (${x.severity})` : 'Not available'],
    ['Exploit status', x.known_exploited ? 'KNOWN EXPLOITED — CISA KEV' : 'Not listed in CISA KEV'],
    ['EPSS', x.epss != null ? `${(Number(x.epss) * 100).toFixed(1)}%` : 'Not available'],
    ['Fixed version', x.fixed_version || 'No fixed version identified'],
    ['Last modified', x.last_modified ? new Date(x.last_modified).toLocaleDateString() : '—']
  ].map(([label,value]) => `
    <div class="detail-field"><label>${escapeHtml(label)}</label><div>${escapeHtml(String(value ?? '—'))}</div></div>
  `).join('');

  document.getElementById('detail-description').innerHTML =
    `<strong>Remediation</strong><br>${escapeHtml(x.remediation || 'Review the vendor advisory and update to a supported fixed version.')}` +
    (x.description ? `<br><br><strong>Description</strong><br>${escapeHtml(x.description)}` : '');

  const links = [];
  if (x.nvd_url) links.push(`<a class="action" href="${escapeHtml(x.nvd_url)}" target="_blank" rel="noopener">NVD →</a>`);
  if (x.vendor_url) links.push(`<a class="action" href="${escapeHtml(x.vendor_url)}" target="_blank" rel="noopener">Vendor advisory →</a>`);
  document.getElementById('detail-actions').innerHTML = links.join('');

  document.getElementById('detail').classList.add('open');
}

function closeDetail() {
  document.getElementById('detail').classList.remove('open');
}

function priorityScore(x) {
  return (x.known_exploited ? 1000 : 0) +
         ((x.cvss || 0) * 20) +
         ((x.epss || 0) * 100);
}

function severityClass(s) {
  return String(s || '').toLowerCase().replace(/[^a-z]/g, '') || 'low';
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}

function timeAgo(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'unknown';
  const seconds = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds/60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds/3600)}h ago`;
  return `${Math.floor(seconds/86400)}d ago`;
}
