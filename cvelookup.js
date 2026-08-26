let allFindings = [];
let activeView = 'all';
let inventory = [
  { name: 'Palo Alto PAN-OS', category: 'Firewall', query: 'PAN-OS' },
  { name: 'Fortinet FortiOS', category: 'Firewall', query: 'FortiOS' },
  { name: 'Cisco ASA', category: 'Firewall', query: 'Cisco Adaptive Security Appliance' },
  { name: 'Azure WAF', category: 'WAF', query: 'Azure Application Gateway' },
  { name: 'F5 BIG-IP', category: 'WAF', query: 'BIG-IP' },
  { name: 'Cloudflare WAF', category: 'WAF', query: 'Cloudflare WAF' },
  { name: 'Microsoft Exchange', category: 'Email & Phishing', query: 'Microsoft Exchange Server' },
  { name: 'Microsoft Outlook', category: 'Email & Phishing', query: 'Microsoft Outlook' },
  { name: 'Mimecast', category: 'Email & Phishing', query: 'Mimecast' },
  { name: 'Microsoft Windows', category: 'Software', query: 'Microsoft Windows' },
  { name: 'Google Chrome', category: 'Software', query: 'Google Chrome' },
  { name: 'Apache HTTP Server', category: 'Software', query: 'Apache HTTP Server' },
  { name: 'WordPress', category: 'Software', query: 'WordPress' }
];

document.addEventListener('DOMContentLoaded', initCves);

async function initCves() {
  populateInventory();
  document.getElementById('lookup-form').addEventListener('submit', lookupProduct);
  document.getElementById('categoryFilter').addEventListener('change', populateInventory);
  bindFilters();
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
    render();
  } catch (err) {
    console.error(err);
    document.getElementById('sync-row').innerHTML =
      '<span class="dot" style="background:#ef4444"></span> Vulnerability feed unavailable';
    document.getElementById('cve-body').innerHTML =
      '<tr><td colspan="8" class="empty">No generated CVE data found yet. Choose an item above to search the NVD.</td></tr>';
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

function populateInventory() {
  const category = document.getElementById('categoryFilter').value;
  const items = inventory.filter(x => category === 'All' || x.category === category);
  document.getElementById('inventory-options').innerHTML = inventory
    .map(x => `<option value="${escapeHtml(x.name)}">${escapeHtml(x.category)}</option>`).join('');
  document.getElementById('inventory-list').innerHTML = items
    .map(x => `<button type="button" class="inventory-item" data-query="${escapeHtml(x.query)}">${escapeHtml(x.name)}</button>`).join('');
  document.querySelectorAll('.inventory-item').forEach(button => {
    button.addEventListener('click', () => {
      document.getElementById('productLookup').value = button.textContent;
      lookupProduct(button.dataset.query);
    });
  });
}

async function lookupProduct(eventOrQuery) {
  if (eventOrQuery?.preventDefault) eventOrQuery.preventDefault();
  const entered = typeof eventOrQuery === 'string' ? eventOrQuery : document.getElementById('productLookup').value.trim();
  if (!entered) return;
  const match = inventory.find(x => x.name.toLowerCase() === entered.toLowerCase());
  const query = match?.query || entered;
  const sync = document.getElementById('sync-row');
  sync.innerHTML = '<span class="dot"></span> Searching NVD…';
  document.getElementById('cve-body').innerHTML = '<tr><td colspan="8" class="empty">Loading CVEs for ' + escapeHtml(entered) + '…</td></tr>';
  try {
    const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=30`);
    if (!response.ok) throw new Error(`NVD HTTP ${response.status}`);
    const data = await response.json();
    allFindings = (data.vulnerabilities || []).map(({ cve }) => normalizeNvdCve(cve, entered, match?.category));
    await enrichFindings(allFindings);
    document.getElementById('metric-assets').textContent = match ? '1' : '—';
    document.getElementById('metric-vulnerable').textContent = allFindings.length;
    document.getElementById('metric-critical').textContent = allFindings.filter(x => x.severity === 'CRITICAL').length;
    document.getElementById('metric-kev').textContent = '—';
    populateAssets();
    render();
    sync.innerHTML = `<span class="dot"></span> NVD results for ${escapeHtml(entered)} · ${allFindings.length} findings`;
  } catch (err) {
    console.error(err);
    sync.innerHTML = '<span class="dot" style="background:#ef4444"></span> NVD lookup unavailable';
    document.getElementById('cve-body').innerHTML = '<tr><td colspan="8" class="empty">Could not retrieve CVEs right now. Try again shortly.</td></tr>';
  }
}

function normalizeNvdCve(cve, assetName, category) {
  const description = cve.descriptions?.find(x => x.lang === 'en')?.value || '';
  const metric = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || cve.metrics?.cvssMetricV2?.[0];
  const score = metric?.cvssData?.baseScore;
  const severity = metric?.cvssData?.baseSeverity || (score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW');
  const references = cve.references || [];
  const patchReference = references.find(reference =>
    (reference.tags || []).some(tag => ['Patch', 'Release Notes', 'Vendor Advisory'].includes(tag))
  );
  return {
    cve_id: cve.id, asset_name: assetName, asset_id: assetName, category,
    vendor: cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria?.split(':')[3] || '',
    product: '', version: 'See affected versions', severity, cvss: score,
    known_exploited: false, epss: null, fixed_version: '',
    patch_available: Boolean(patchReference), vendor_url: normalizeVendorUrl(patchReference?.url), source: 'NVD', description,
    last_modified: cve.lastModified, nvd_url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`
  };
}

async function enrichFindings(findings) {
  const cveIds = findings.map(x => x.cve_id).filter(Boolean);
  if (!cveIds.length) return;

  const epssResult = await Promise.allSettled([
    fetch(`https://api.first.org/data/v1/epss?${new URLSearchParams({ cve: cveIds.join(',') })}`).then(response => {
      if (!response.ok) throw new Error(`EPSS HTTP ${response.status}`);
      return response.json();
    })
  ]);

  const epssById = new Map();
  if (epssResult[0].status === 'fulfilled') {
    (epssResult[0].value.data || []).forEach(item => epssById.set(item.cve, Number(item.epss)));
  }

  findings.forEach(item => {
    if (epssById.has(item.cve_id)) item.epss = epssById.get(item.cve_id);
  });
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
  document.addEventListener('click', e => {
    if (e.target.closest('#detail-close')) closeDetail();
  });
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
    if (activeView === 'patch' && !hasPatchGuidance(x)) return false;
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
        <div class="muted">${escapeHtml(x.category || 'Inventory item')}</div>
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
        ${patchBadge(x)}
      </td>
      <td><span class="muted">${escapeHtml(x.source || 'NVD')}</span></td>
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
    ['Patch status', patchStatus(x)],
    ['Sources', x.source || 'NVD'],
    ['Last modified', x.last_modified ? new Date(x.last_modified).toLocaleDateString() : '—']
  ].map(([label,value]) => `
    <div class="detail-field"><label>${escapeHtml(label)}</label><div>${escapeHtml(String(value ?? '—'))}</div></div>
  `).join('');

  document.getElementById('detail-description').innerHTML =
    `<strong>Remediation</strong><br>${escapeHtml(x.remediation || 'Review the vendor advisory and update to a supported fixed version.')}` +
    (x.description ? `<br><br><strong>Description</strong><br>${escapeHtml(x.description)}` : '');

  const links = [];
  if (x.nvd_url) links.push(`<a class="action" href="${escapeHtml(x.nvd_url)}" target="_blank" rel="noopener">NVD →</a>`);
  links.push(`<a class="action" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(x.cve_id)}" target="_blank" rel="noopener">CISA KEV →</a>`);
  if (x.vendor_url) links.push(`<a class="action" href="${escapeHtml(normalizeVendorUrl(x.vendor_url))}" target="_blank" rel="noopener">Vendor advisory →</a>`);
  document.getElementById('detail-actions').innerHTML = links.join('');

  const detail = document.getElementById('detail');
  detail.classList.add('open');
  detail.setAttribute('aria-hidden', 'false');
}

function closeDetail() {
  const detail = document.getElementById('detail');
  detail.classList.remove('open');
  detail.setAttribute('aria-hidden', 'true');
}

function hasPatchGuidance(x) {
  return Boolean(x.fixed_version || x.patch_available || x.vendor_url);
}

function patchStatus(x) {
  if (x.fixed_version) return `Fixed version: ${x.fixed_version}`;
  if (x.patch_available) return 'Vendor patch or release guidance available';
  if (x.vendor_url) return 'Vendor advisory available; fixed version not specified';
  return 'Patch status not published';
}

function patchBadge(x) {
  if (x.fixed_version) return `<span class="badge patch">Fix: ${escapeHtml(x.fixed_version)}</span>`;
  if (x.patch_available) return '<span class="badge advisory">Patch guidance</span>';
  if (x.vendor_url) return '<span class="badge patch-unknown">Check advisory</span>';
  return '<span class="badge no-patch">Patch unknown</span>';
}

function normalizeVendorUrl(value) {
  if (!value) return '';
  return String(value).replace(
    /^http:\/\/fortiguard\.fortinet\.com\//i,
    'https://www.fortiguard.com/'
  );
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
