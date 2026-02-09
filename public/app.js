const state = {
  dataset: 'extracted',
  page: 0,
  limit: 10,
  query: '',
  summary: null,
  dataStatus: null,
  currentUser: null,
  authEnabled: true,
  authSource: null,
  isAdmin: false,
  onlyUnreviewed: false
};

const escapeHtml = (str = '') => String(str)
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

const evalQuestions = {
  qa: [
    {
      id: 'qa_reflects',
      text: 'Is this question correctly grounded in the abstract’s findings?'
    },
    {
      id: 'qa_quality',
      text: 'Does this QA pair stand alone as a high-value clinical knowledge statement?'
    }
  ],
  extracted: [
    {
      id: 'extracted_accuracy',
      text: 'Does this extracted summary accurately represent the abstract’s findings?'
    }
  ]
};

let datasets = [];
let pendingResponse = null;
let compareSelection = null;
let searchTimer = null;

const datasetListEl = document.getElementById('dataset-list');
const itemsEl = document.getElementById('items');
const datasetTitleEl = document.getElementById('dataset-title');
const pageInfoEl = document.getElementById('page-info');
const searchInput = document.getElementById('search-input');
const statsEl = document.getElementById('stats');
const progressEl = document.getElementById('progress');

const currentUserEl = document.getElementById('current-user');
const logoutBtn = document.getElementById('logout-btn');

const modal = document.getElementById('modal');
const modalQuestion = document.getElementById('modal-question');
const modalSubtext = document.getElementById('modal-subtext');
const modalConfirm = document.getElementById('modal-confirm');
const modalCancel = document.getElementById('modal-cancel');
const modalAbort = document.getElementById('modal-abort');

const compareModal = document.getElementById('compare-modal');
const compareListEl = document.getElementById('compare-list');
const compareSubmit = document.getElementById('compare-submit');
const compareClose = document.getElementById('compare-close');

const summaryModal = document.getElementById('summary-modal');
const summaryBtn = document.getElementById('summary-btn');
const summaryClose = document.getElementById('summary-close');
const summaryContent = document.getElementById('summary-content');
const exportButtons = document.getElementById('export-buttons');

const loginModal = document.getElementById('login-modal');
const loginForm = document.getElementById('login-form');
const loginUsername = document.getElementById('login-username');
const loginPassword = document.getElementById('login-password');
const loginError = document.getElementById('login-error');

const adminPanel = document.getElementById('admin-panel');
const uploadExtractedInput = document.getElementById('upload-extracted');
const uploadQaInput = document.getElementById('upload-qa');
const uploadBtn = document.getElementById('upload-btn');
const reloadDataBtn = document.getElementById('reload-data-btn');
const dataStatusEl = document.getElementById('data-status');

const newUsernameInput = document.getElementById('new-username');
const newDisplaynameInput = document.getElementById('new-displayname');
const newPasswordInput = document.getElementById('new-password');
const newRoleSelect = document.getElementById('new-role');
const createUserBtn = document.getElementById('create-user-btn');
const userListEl = document.getElementById('user-list');

const unreviewedToggle = document.getElementById('unreviewed-toggle');
const downloadCsvBtn = document.getElementById('download-csv');
const downloadJsonBtn = document.getElementById('download-json');

const toast = document.getElementById('toast');

function setCurrentUser(user, authEnabled = true) {
  state.authEnabled = authEnabled;
  state.currentUser = user || null;
  if (!authEnabled) {
    currentUserEl.textContent = 'Open access mode (login disabled)';
    logoutBtn.classList.add('hidden');
    return;
  }
  if (user?.username) {
    const label = user.displayName && user.displayName !== user.username
      ? `${user.displayName} (${user.username})`
      : user.username;
    currentUserEl.textContent = `Signed in: ${label}`;
    logoutBtn.classList.remove('hidden');
  } else {
    currentUserEl.textContent = 'Not signed in';
    logoutBtn.classList.add('hidden');
  }
}

function openLoginModal(message = '') {
  loginError.textContent = message;
  loginError.classList.toggle('hidden', !message);
  loginModal.classList.remove('hidden');
  loginUsername.focus();
}

function closeLoginModal() {
  loginModal.classList.add('hidden');
  loginError.classList.add('hidden');
  loginError.textContent = '';
  loginPassword.value = '';
}

function clearVisibleData() {
  itemsEl.innerHTML = '';
  statsEl.innerHTML = '';
  progressEl.innerHTML = '';
  pageInfoEl.textContent = '';
  summaryContent.innerHTML = '';
  exportButtons.innerHTML = '';
  dataStatusEl.innerHTML = '';
  userListEl.innerHTML = '';
}

function updateAdminPanel() {
  if (!adminPanel) return;
  adminPanel.classList.toggle('hidden', !state.isAdmin);
}

function formatFileStatus(file) {
  if (!file) return 'Unknown';
  if (!file.exists) return 'Missing';
  if (file.error) return `Error: ${file.error}`;
  return 'Ready';
}

async function fetchDataStatus() {
  try {
    const res = await apiFetch('/api/data-status');
    if (!res.ok) throw new Error(await readErrorMessage(res, 'Failed to load data status'));
    state.dataStatus = await res.json();
    renderDataStatus();
  } catch (err) {
    console.error(err);
    state.dataStatus = null;
    dataStatusEl.innerHTML = '';
  }
}

function renderDataStatus() {
  if (!dataStatusEl) return;
  const status = state.dataStatus;
  if (!status?.files) {
    dataStatusEl.innerHTML = '<div class="small muted">No data status available.</div>';
    return;
  }

  const extracted = status.files.extracted;
  const qa = status.files.qa;
  const extractedFormat = extracted?.structuredColumnsPresent
    ? 'structured columns'
    : (extracted?.jsonExtractionColumnsPresent ? 'ex_* JSON columns' : 'gpt_output markdown');
  dataStatusEl.innerHTML = `
    <div class="status-row"><strong>Source dir:</strong> ${escapeHtml(status.sourceDataDir || '')}</div>
    <div class="status-row">
      <strong>Extraction:</strong> ${escapeHtml(formatFileStatus(extracted))}<br>
      <span class="small muted">${escapeHtml(extracted?.filename || 'extracted_insights.csv')} · ${extracted?.items ?? 0} items · ${extracted?.uniquePmids ?? 0} studies · ${escapeHtml(extractedFormat)}</span>
    </div>
    <div class="status-row">
      <strong>Q&amp;A:</strong> ${escapeHtml(formatFileStatus(qa))}<br>
      <span class="small muted">${escapeHtml(qa?.filename || 'qa_pairs.csv')} · ${qa?.items ?? 0} items · ${qa?.uniquePmids ?? 0} studies</span>
    </div>
    <div class="status-row small muted">Loaded at: ${escapeHtml(status.loadedAt || 'n/a')}</div>
  `;
}

async function fetchAdminUsers() {
  if (!state.isAdmin) return;
  try {
    const res = await apiFetch('/api/admin/users');
    if (!res.ok) throw new Error(await readErrorMessage(res, 'Failed to load users'));
    const data = await res.json();
    renderUserList(data.users || [], Boolean(data.mutable));
  } catch (err) {
    console.error(err);
    userListEl.innerHTML = '<div class="small muted">Unable to load user list.</div>';
  }
}

function renderUserList(users, mutable) {
  if (!userListEl) return;
  createUserBtn.disabled = !mutable;
  [newUsernameInput, newDisplaynameInput, newPasswordInput, newRoleSelect].forEach(el => {
    if (!el) return;
    el.disabled = !mutable;
  });
  if (!mutable) {
    userListEl.innerHTML = '<div class="small muted">User management is locked because users are coming from environment variables.</div>';
    return;
  }

  if (!users.length) {
    userListEl.innerHTML = '<div class="small muted">No users yet. Create the first expert account above.</div>';
    return;
  }

  const current = state.currentUser?.username || '';
  userListEl.innerHTML = users.map(u => {
    const isSelf = u.username === current;
    return `
      <div class="user-row">
        <div>
          <div class="user-name"><strong>${escapeHtml(u.username)}</strong> <span class="pill ${u.role === 'admin' ? 'pill-admin' : 'pill-expert'}">${escapeHtml(u.role || 'expert')}</span></div>
          <div class="small muted">${escapeHtml(u.displayName || '')}</div>
        </div>
        <div class="user-actions">
          <button class="ghost" data-reset-user="${escapeHtml(u.username)}">Reset password</button>
          <button class="ghost danger" data-delete-user="${escapeHtml(u.username)}" ${isSelf ? 'disabled' : ''}>Delete</button>
        </div>
      </div>
    `;
  }).join('');

  queryAll('[data-reset-user]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const username = btn.dataset.resetUser;
      const password = window.prompt(`Set a new password for ${username} (min 8 chars):`);
      if (!password) return;
      try {
        const res = await apiFetch(`/api/admin/users/${encodeURIComponent(username)}/password`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        if (!res.ok) throw new Error(await readErrorMessage(res, 'Password reset failed'));
        showToast('Password updated');
      } catch (err) {
        console.error(err);
        showToast('Password reset failed');
      }
    });
  });

  queryAll('[data-delete-user]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const username = btn.dataset.deleteUser;
      if (!username) return;
      if (!window.confirm(`Delete user ${username}?`)) return;
      try {
        const res = await apiFetch(`/api/admin/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
        if (!res.ok) throw new Error(await readErrorMessage(res, 'Delete failed'));
        await fetchAdminUsers();
        showToast('User deleted');
      } catch (err) {
        console.error(err);
        showToast('Delete failed');
      }
    });
  });
}

async function readErrorMessage(res, fallback) {
  try {
    const data = await res.json();
    if (data?.error) return data.error;
  } catch {
    // ignore response parse failures for fallback message
  }
  return fallback;
}

async function apiFetch(url, options = {}, { allowUnauthorized = false } = {}) {
  const res = await fetch(url, options);
  if (res.status === 401 && !allowUnauthorized) {
    setCurrentUser(null, true);
    clearVisibleData();
    openLoginModal('Session expired. Sign in again.');
    throw new Error('Authentication required');
  }
  return res;
}

async function ensureAuthenticated() {
  try {
    const res = await apiFetch('/api/auth/me', {}, { allowUnauthorized: true });
    if (res.status === 401) {
      setCurrentUser(null, true);
      state.isAdmin = false;
      state.authSource = null;
      openLoginModal();
      return false;
    }
    if (!res.ok) {
      throw new Error(await readErrorMessage(res, 'Auth check failed'));
    }
    const data = await res.json();
    state.isAdmin = Boolean(data.isAdmin);
    state.authSource = data.authSource || null;
    setCurrentUser(data.user, data.authEnabled !== false);
    updateAdminPanel();
    closeLoginModal();
    return true;
  } catch (err) {
    console.error(err);
    setCurrentUser(null, true);
    state.isAdmin = false;
    state.authSource = null;
    updateAdminPanel();
    openLoginModal('Unable to verify session. Try again.');
    return false;
  }
}

async function init() {
  const ready = await ensureAuthenticated();
  if (!ready) return;
  await fetchDataStatus();
  if (state.isAdmin) {
    await fetchAdminUsers();
  }
  await fetchDatasets();
  await refreshSummary();
  await loadItems();
}

async function fetchDatasets() {
  const res = await apiFetch('/api/datasets');
  if (!res.ok) throw new Error(await readErrorMessage(res, 'Failed to load datasets'));
  const data = await res.json();
  const order = ['extracted', 'qa'];
  datasets = (data.datasets || []).slice().sort((a, b) => {
    const ai = order.indexOf(a.key);
    const bi = order.indexOf(b.key);
    return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
  });
  if (!datasets.some(d => d.key === state.dataset) && datasets.length) {
    state.dataset = datasets[0].key;
  }
  renderDatasetList();
  updateStats();
}

function renderDatasetList() {
  datasetListEl.innerHTML = '';
  datasets.forEach(ds => {
    const div = document.createElement('div');
    div.className = `dataset-card ${state.dataset === ds.key ? 'active' : ''}`;
    const fileLine = ds.sourceFile
      ? `<div class="small muted">Source: ${escapeHtml(ds.sourceFile)}${ds.sourceExists ? '' : ' (missing)'}</div>`
      : '';
    const warn = !ds.sourceExists && ds.sourceError
      ? `<div class="small warn">Issue: ${escapeHtml(ds.sourceError)}</div>`
      : '';
    div.innerHTML = `
      <h3>${escapeHtml(ds.label)}</h3>
      <p>${ds.count} items · ${ds.uniquePmids} studies</p>
      ${fileLine}
      ${warn}
    `;
    div.onclick = async () => {
      state.dataset = ds.key;
      state.page = 0;
      state.query = '';
      searchInput.value = '';
      renderDatasetList();
      updateStats();
      await refreshSummary();
      await loadItems();
    };
    datasetListEl.appendChild(div);
  });
}

function updateStats() {
  const ds = datasets.find(d => d.key === state.dataset);
  if (!ds) return;
  statsEl.innerHTML = `
    <div><strong>Items:</strong> ${ds.count}</div>
    <div><strong>Studies:</strong> ${ds.uniquePmids} <span class="muted">(unique PMIDs)</span></div>
    ${ds.sourceFile ? `<div><strong>Source:</strong> ${escapeHtml(ds.sourceFile)} ${ds.sourceExists ? '' : '<span class="warn">(missing)</span>'}</div>` : ''}
  `;
  datasetTitleEl.textContent = ds.label;
  updateProgressBar();
}

function updateProgressBar() {
  const summary = state.summary;
  const ds = datasets.find(d => d.key === state.dataset);
  if (!summary || !ds) {
    progressEl.innerHTML = '';
    return;
  }
  const reviewedByUser = summary.reviewedByUser ?? summary.reviewed ?? 0;
  const reviewedGlobal = summary.reviewedGlobal ?? 0;
  const pct = Math.min(100, Math.round((reviewedByUser / Math.max(1, ds.count)) * 100));
  progressEl.innerHTML = `
    <div><strong>Reviewed by you:</strong> ${reviewedByUser} / ${ds.count} (${pct}%)</div>
    <div class="small muted">Reviewed (anyone): ${reviewedGlobal} / ${ds.count}</div>
    <div class="progress-bar"><span style="width:${pct}%"></span></div>
  `;
}

async function refreshSummary() {
  const params = new URLSearchParams({ dataset: state.dataset });
  const res = await apiFetch(`/api/summary?${params.toString()}`);
  if (!res.ok) throw new Error(await readErrorMessage(res, 'Failed to load summary'));
  const data = await res.json();
  state.summary = data;
  updateProgressBar();
}

async function loadItems() {
  const params = new URLSearchParams({
    dataset: state.dataset,
    offset: state.page * state.limit,
    limit: state.limit,
    q: state.query,
    unreviewed: state.onlyUnreviewed ? '1' : '0'
  });
  const res = await apiFetch(`/api/items?${params.toString()}`);
  if (!res.ok) throw new Error(await readErrorMessage(res, 'Failed to load items'));
  const data = await res.json();
  renderItems(data.items || []);
  const totalPages = Math.max(Math.ceil((data.total || 1) / state.limit), 1);
  pageInfoEl.textContent = `Page ${state.page + 1} / ${totalPages}`;
  document.getElementById('prev-page').disabled = state.page === 0;
  document.getElementById('next-page').disabled = state.page + 1 >= totalPages;
}

function renderItems(items) {
  itemsEl.innerHTML = '';
  if (!items.length) {
    const ds = datasets.find(d => d.key === state.dataset);
    const box = document.createElement('div');
    box.className = 'empty-state';
    if (ds && ds.count === 0 && !state.query) {
      const file = ds.sourceFile || '(unknown source file)';
      box.innerHTML = `
        <h3>No validation data yet</h3>
        <p class="muted">An admin must upload the dataset files before experts can review items.</p>
        <div class="callout">
          <div><strong>Upload required:</strong> ${escapeHtml(file)}</div>
          <div class="small muted">Admin sidebar: Upload Validation Files</div>
        </div>
      `;
    } else if (state.onlyUnreviewed && !state.query) {
      box.innerHTML = `
        <h3>All caught up</h3>
        <p class="muted">You have reviewed everything that matches the current filters.</p>
      `;
    } else {
      box.innerHTML = `
        <h3>No items found</h3>
        <p class="muted">Try clearing search, switching datasets, or turning off the unreviewed filter.</p>
      `;
    }
    itemsEl.appendChild(box);
    return;
  }

  items.forEach(item => {
    const card = document.createElement('article');
    card.className = 'item-card';

    const header = document.createElement('div');
    header.className = 'item-header';
    const statusPill = item.userReviewedAll
      ? '<span class="pill pill-done">Completed</span>'
      : '<span class="pill pill-pending">In progress</span>';
    header.innerHTML = `
      <div>
        <div class="item-title">
          <h3>${escapeHtml(item.title || 'Untitled Study')}</h3>
          ${statusPill}
        </div>
        <div class="meta">PMID ${escapeHtml(item.pmid || 'n/a')} · ${escapeHtml(item.journal || 'Journal n/a')} (${escapeHtml(item.year || 'n/a')})</div>
      </div>
      ${state.dataset === 'qa' ? `<button class="secondary" data-compare="${escapeHtml(item.pmid)}" data-id="${escapeHtml(item.id)}">Compare QA options</button>` : ''}
    `;
    card.appendChild(header);

    if (state.dataset === 'qa') {
      card.appendChild(buildParagraph('qa-question', `Q: ${escapeHtml(item.question)}`));
      card.appendChild(buildParagraph('qa-answer', `<strong>Answer:</strong> ${escapeHtml(item.answer)}`));

      const rationale = document.createElement('details');
      rationale.className = 'rationale';
      rationale.innerHTML = `<summary>View rationale</summary><p>${escapeHtml(item.explanation)}</p>`;
      card.appendChild(rationale);
    } else {
      if (item.summary) {
        const summary = document.createElement('div');
        summary.className = 'extraction-summary';
        summary.innerHTML = `<strong>Summary:</strong> ${escapeHtml(item.summary)}`;
        card.appendChild(summary);
      }

      const grid = document.createElement('div');
      grid.className = 'section-stack';
      const fields = [
        { key: 'population', label: 'Population Studied' },
        { key: 'symptoms', label: 'Symptoms' },
        { key: 'riskFactors', label: 'Risk Factors / Triggers' },
        { key: 'interventions', label: 'Interventions / Treatments' },
        { key: 'outcomes', label: 'Outcomes' }
      ];
      fields.forEach(({ key, label }) => {
        const sec = document.createElement('div');
        sec.className = `section-card section-${key}`;
        const bullets = (item.categorized?.[key] || []).filter(Boolean);
        sec.innerHTML = `
          <h4>${label}</h4>
          ${bullets.length ? bullets.map(b => `<div>• ${escapeHtml(b)}</div>`).join('') : '<div class="empty">Not captured</div>'}
        `;
        grid.appendChild(sec);
      });
      card.appendChild(grid);

      const rawDetails = document.createElement('details');
      rawDetails.className = 'rationale';
      rawDetails.innerHTML = `
        <summary>Show extraction details</summary>
        ${(item.parsed?.sections || []).map(section => `<p><strong>${escapeHtml(section.heading)}</strong><br>${section.bullets.map(b => escapeHtml(b)).join('<br>')}</p>`).join('')}
      `;
      card.appendChild(rawDetails);
    }

    const abstract = document.createElement('div');
    abstract.className = 'abstract';
    const abstractText = escapeHtml(item.abstract || '').replace(/\n/g, '<br>');
    abstract.innerHTML = `<strong>Abstract:</strong><br>${abstractText}`;
    card.appendChild(abstract);

    const validation = document.createElement('div');
    validation.className = 'validation-block';

    evalQuestions[state.dataset].forEach(q => {
      const row = document.createElement('div');
      row.className = 'validation-question';

      const left = document.createElement('div');
      left.className = 'question-left';
      const prompt = document.createElement('p');
      prompt.textContent = q.text;
      left.appendChild(prompt);

      const saved = item.userReview?.[q.id];
      const savedLine = document.createElement('div');
      savedLine.className = 'saved-line';
      if (saved?.answer) {
        savedLine.textContent = `Saved: ${saved.answer.toUpperCase()} (${saved.sure ? 'confident' : 'unsure'})`;
      } else {
        savedLine.textContent = 'Not answered yet';
      }
      left.appendChild(savedLine);
      row.appendChild(left);

      const buttons = document.createElement('div');
      buttons.className = 'btn-group';

      const yesBtn = document.createElement('button');
      yesBtn.className = 'btn yes';
      yesBtn.textContent = 'Yes';
      if (saved?.answer === 'yes') yesBtn.classList.add('selected');
      yesBtn.onclick = () => openConfirm({ dataset: state.dataset, itemId: item.id, questionId: q.id, answer: 'yes', questionText: q.text });

      const noBtn = document.createElement('button');
      noBtn.className = 'btn no';
      noBtn.textContent = 'No';
      if (saved?.answer === 'no') noBtn.classList.add('selected');
      noBtn.onclick = () => openConfirm({ dataset: state.dataset, itemId: item.id, questionId: q.id, answer: 'no', questionText: q.text });

      buttons.appendChild(yesBtn);
      buttons.appendChild(noBtn);
      row.appendChild(buttons);
      validation.appendChild(row);
    });

    card.appendChild(validation);
    itemsEl.appendChild(card);
  });

  if (state.dataset === 'qa') {
    queryAll('[data-compare]').forEach(btn => {
      btn.addEventListener('click', () => openCompare(btn.dataset.compare));
    });
  }
}

function buildParagraph(className, html) {
  const p = document.createElement('p');
  p.className = className;
  p.innerHTML = html;
  return p;
}

function openConfirm(payload) {
  pendingResponse = payload;
  modalQuestion.textContent = payload.questionText;
  modalSubtext.textContent = `You selected “${payload.answer.toUpperCase()}”. Choose confidence to save, or cancel to go back.`;
  modal.classList.remove('hidden');
}

modalConfirm.onclick = async () => {
  if (!pendingResponse) return;
  await submitResponse({ ...pendingResponse, sure: true });
  closeModal();
};

modalCancel.onclick = async () => {
  if (!pendingResponse) return;
  await submitResponse({ ...pendingResponse, sure: false });
  closeModal();
};

modalAbort.onclick = () => {
  closeModal();
};

function closeModal() {
  modal.classList.add('hidden');
  pendingResponse = null;
}

modal.addEventListener('click', (event) => {
  if (event.target === modal) closeModal();
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !modal.classList.contains('hidden')) {
    closeModal();
  }
});

async function submitResponse(payload) {
  try {
    const res = await apiFetch('/api/responses', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error(await readErrorMessage(res, 'Failed to submit response'));
    await refreshSummary();
    await loadItems();
    showToast('Response recorded');
  } catch (err) {
    console.error(err);
    showToast('Submission failed');
  }
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.remove('hidden');
  setTimeout(() => toast.classList.add('hidden'), 2200);
}

async function openCompare(pmid) {
  const params = new URLSearchParams({ dataset: state.dataset, pmid });
  try {
    const res = await apiFetch(`/api/compare-options?${params.toString()}`);
    if (!res.ok) throw new Error(await readErrorMessage(res, 'Failed to load compare options'));
    const data = await res.json();
    const items = data.items || [];
    compareSelection = { pmid, choiceId: items[0]?.id || null };

    compareListEl.innerHTML = '';
    items.forEach(item => {
      const card = document.createElement('div');
      card.className = 'compare-card';
      card.innerHTML = `
        <header>
          <label>
            <input type="radio" name="compare-choice" value="${item.id}" ${item.id === compareSelection.choiceId ? 'checked' : ''} />
            ${item.question.slice(0, 80)}
          </label>
          <span class="meta">PMID ${item.pmid}</span>
        </header>
        <div><strong>Answer:</strong> ${item.answer}</div>
        <div><strong>Explanation:</strong> ${item.explanation}</div>
      `;
      queryAll('input[type="radio"]', card).forEach(radio => {
        radio.addEventListener('change', evt => {
          compareSelection.choiceId = evt.target.value;
        });
      });
      compareListEl.appendChild(card);
    });
    compareModal.classList.remove('hidden');
  } catch (err) {
    console.error(err);
    showToast('Could not open compare options');
  }
}

compareSubmit.onclick = async () => {
  if (!compareSelection || !compareSelection.choiceId) {
    showToast('Select an option first');
    return;
  }
  try {
    const res = await apiFetch('/api/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dataset: state.dataset, pmid: compareSelection.pmid, choiceId: compareSelection.choiceId })
    });
    if (!res.ok) throw new Error(await readErrorMessage(res, 'Submit failed'));
    showToast('Comparison saved');
    compareModal.classList.add('hidden');
  } catch (err) {
    console.error(err);
    showToast('Comparison failed');
  }
};

compareClose.onclick = () => {
  compareModal.classList.add('hidden');
};

summaryBtn.onclick = async () => {
  try {
    await refreshSummary();
    renderSummaryModal();
    summaryModal.classList.remove('hidden');
  } catch (err) {
    console.error(err);
    showToast('Failed to refresh summary');
  }
};

summaryClose.onclick = () => {
  summaryModal.classList.add('hidden');
};

function renderSummaryModal() {
  const summary = state.summary || { questionSummaries: {}, compare: {}, totalDecisions: 0 };
  summaryContent.innerHTML = '';
  exportButtons.innerHTML = '';

  const meta = document.createElement('div');
  meta.className = 'meta';
  meta.innerHTML = `<strong>Total decisions:</strong> ${summary.totalDecisions || 0}`;
  summaryContent.appendChild(meta);

  Object.entries(summary.questionSummaries || {}).forEach(([questionId, info]) => {
    const section = document.createElement('section');
    section.innerHTML = `<h4>${humanizeQuestion(questionId)}</h4>`;

    const countsRow = document.createElement('div');
    countsRow.className = 'badge-row';
    const counts = info.counts || {};
    ['yes_sure', 'yes_unsure', 'no_sure', 'no_unsure'].forEach(key => {
      if (counts[key]) {
        const badge = document.createElement('span');
        badge.className = 'badge';
        badge.textContent = `${key.replace('_', ' ')} · ${counts[key]}`;
        countsRow.appendChild(badge);
      }
    });
    section.appendChild(countsRow);

    const yesList = buildRecordList(info.yes || [], 'Validated (Yes)');
    const noList = buildRecordList(info.no || [], 'Flagged (No)');
    section.appendChild(yesList);
    section.appendChild(noList);

    const exportRow = document.createElement('div');
    exportRow.className = 'export-group';
    exportRow.innerHTML = `
      <button class="secondary" data-export-question="${questionId}" data-decision="">Export CSV</button>
      <button class="secondary" data-export-question="${questionId}" data-decision="yes">Export Yes Only</button>
      <button class="secondary" data-export-question="${questionId}" data-decision="no">Export No Only</button>
    `;
    section.appendChild(exportRow);

    summaryContent.appendChild(section);
  });

  exportButtons.innerHTML = `
    <button class="cta" data-export-all="csv">Download results (CSV)</button>
    <button class="cta ghost" data-export-all="json">Download results (JSON)</button>
  `;

  queryAll('[data-export-question]').forEach(btn => {
    btn.addEventListener('click', () => exportJudgements({
      questionId: btn.dataset.exportQuestion,
      decision: btn.dataset.decision || undefined,
      format: 'csv'
    }));
  });

  queryAll('[data-export-all]').forEach(btn => {
    btn.addEventListener('click', () => exportJudgements({ format: btn.dataset.exportAll }));
  });

}

function buildRecordList(records, heading) {
  const container = document.createElement('div');
  container.className = 'record-list';
  const title = document.createElement('h4');
  title.textContent = heading;
  container.appendChild(title);
  if (!records.length) {
    const p = document.createElement('p');
    p.textContent = 'No responses yet.';
    container.appendChild(p);
    return container;
  }
  records.slice(-5).reverse().forEach(record => {
    const item = document.createElement('div');
    item.className = 'record-item';
    item.innerHTML = `
      <h4>${escapeHtml(record.title || 'Untitled Study')} (${escapeHtml(record.pmid || 'PMID n/a')})</h4>
      <p><strong>Timestamp:</strong> ${escapeHtml(new Date(record.timestamp).toLocaleString())}</p>
      <p><strong>Reviewer:</strong> ${escapeHtml(record.reviewer || 'unknown')}</p>
      <p><strong>Details:</strong> ${escapeHtml(renderRecordSummary(record))}</p>
      <p><strong>Confidence:</strong> ${record.sure ? 'Reviewer confident' : 'Reviewer unsure'}</p>
    `;
    container.appendChild(item);
  });
  return container;
}

function renderRecordSummary(record) {
  if (record.dataset === 'qa') {
    return `${record.content?.question || 'Question'} → ${record.content?.answer || 'Answer'}`;
  }
  return record.content?.summary || 'See extraction notes';
}

function humanizeQuestion(id) {
  const question = [...evalQuestions.qa, ...evalQuestions.extracted].find(q => q.id === id);
  return question ? question.text : id;
}

async function exportJudgements({ questionId, decision, format = 'csv' }) {
  try {
    const params = new URLSearchParams({ dataset: state.dataset, format });
    if (questionId) params.append('questionId', questionId);
    if (decision) params.append('decision', decision);
    const res = await apiFetch(`/api/export?${params.toString()}`);
    if (!res.ok) throw new Error(await readErrorMessage(res, 'Export failed'));
    if (format === 'json') {
      const data = await res.json();
      download(JSON.stringify(data, null, 2), `${state.dataset}-${questionId || 'all'}.json`, 'application/json');
    } else {
      const blob = await res.blob();
      const arrayBuffer = await blob.arrayBuffer();
      const csv = new TextDecoder().decode(arrayBuffer);
      download(csv, `${state.dataset}-${questionId || 'all'}${decision ? '-' + decision : ''}.csv`, 'text/csv');
    }
  } catch (err) {
    console.error(err);
    showToast('Export failed');
  }
}

function download(content, filename, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

document.getElementById('prev-page').onclick = async () => {
  if (state.page > 0) {
    state.page -= 1;
    await loadItems();
  }
};

document.getElementById('next-page').onclick = async () => {
  state.page += 1;
  await loadItems();
};

searchInput.addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    state.query = searchInput.value.trim();
    state.page = 0;
    loadItems();
  }, 260);
});

unreviewedToggle?.addEventListener('change', async () => {
  state.onlyUnreviewed = Boolean(unreviewedToggle.checked);
  state.page = 0;
  await loadItems();
});

downloadCsvBtn?.addEventListener('click', () => {
  exportJudgements({ format: 'csv' });
});

downloadJsonBtn?.addEventListener('click', () => {
  exportJudgements({ format: 'json' });
});

uploadBtn?.addEventListener('click', async () => {
  const extractedFile = uploadExtractedInput?.files?.[0] || null;
  const qaFile = uploadQaInput?.files?.[0] || null;
  if (!extractedFile && !qaFile) {
    showToast('Select at least one file to upload');
    return;
  }
  uploadBtn.disabled = true;
  try {
    const uploadOne = async (file, expected) => {
      const res = await apiFetch(`/api/admin/upload/${encodeURIComponent(expected)}`, {
        method: 'PUT',
        headers: { 'Content-Type': file.type || 'application/octet-stream' },
        body: file
      });
      if (!res.ok) throw new Error(await readErrorMessage(res, `Upload failed: ${expected}`));
      return res.json();
    };

    if (extractedFile) await uploadOne(extractedFile, 'extracted_insights.csv');
    if (qaFile) await uploadOne(qaFile, 'qa_pairs.csv');

    uploadExtractedInput.value = '';
    uploadQaInput.value = '';

    await fetchDataStatus();
    await fetchDatasets();
    await refreshSummary();
    await loadItems();
    showToast('Upload complete');
  } catch (err) {
    console.error(err);
    showToast('Upload failed');
  } finally {
    uploadBtn.disabled = false;
  }
});

reloadDataBtn?.addEventListener('click', async () => {
  reloadDataBtn.disabled = true;
  try {
    const res = await apiFetch('/api/admin/reload-data', { method: 'POST' });
    if (!res.ok) throw new Error(await readErrorMessage(res, 'Reload failed'));
    await fetchDataStatus();
    await fetchDatasets();
    await refreshSummary();
    await loadItems();
    showToast('Data reloaded');
  } catch (err) {
    console.error(err);
    showToast('Reload failed');
  } finally {
    reloadDataBtn.disabled = false;
  }
});

createUserBtn?.addEventListener('click', async () => {
  const username = newUsernameInput.value.trim();
  const displayName = newDisplaynameInput.value.trim();
  const password = newPasswordInput.value;
  const role = newRoleSelect.value;

  if (!username || !password) {
    showToast('Username + password required');
    return;
  }
  createUserBtn.disabled = true;
  try {
    const res = await apiFetch('/api/admin/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, displayName, password, role })
    });
    if (!res.ok) throw new Error(await readErrorMessage(res, 'Create user failed'));
    newUsernameInput.value = '';
    newDisplaynameInput.value = '';
    newPasswordInput.value = '';
    newRoleSelect.value = 'expert';
    await fetchAdminUsers();
    showToast('User created');
  } catch (err) {
    console.error(err);
    showToast('Create user failed');
  } finally {
    createUserBtn.disabled = false;
  }
});

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  loginError.classList.add('hidden');
  loginError.textContent = '';

  const payload = {
    username: loginUsername.value.trim(),
    password: loginPassword.value
  };

  if (!payload.username || !payload.password) {
    openLoginModal('Both username and password are required.');
    return;
  }

  try {
    const res = await apiFetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }, { allowUnauthorized: true });

    if (!res.ok) {
      openLoginModal(await readErrorMessage(res, 'Login failed'));
      return;
    }

    const data = await res.json();
    state.isAdmin = Boolean(data.user?.role === 'admin');
    state.authSource = data.authSource || null;
    setCurrentUser(data.user, data.authEnabled !== false);
    updateAdminPanel();
    closeLoginModal();
    await fetchDataStatus();
    if (state.isAdmin) await fetchAdminUsers();
    await fetchDatasets();
    await refreshSummary();
    await loadItems();
    showToast('Signed in');
  } catch (err) {
    console.error(err);
    openLoginModal('Login failed. Try again.');
  }
});

logoutBtn.addEventListener('click', async () => {
  try {
    await apiFetch('/api/auth/logout', { method: 'POST' }, { allowUnauthorized: true });
  } catch (err) {
    console.error(err);
  }
  setCurrentUser(null, true);
  state.isAdmin = false;
  state.authSource = null;
  updateAdminPanel();
  clearVisibleData();
  openLoginModal('Signed out.');
  showToast('Signed out');
});

function queryAll(selector, root = document) {
  return Array.from(root.querySelectorAll(selector));
}

init();
