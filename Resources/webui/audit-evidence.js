/* Read-only GitHub evidence and contextual conversation in the native workspace. */
const auditRepositoryStatuses = new Map();
let auditConversation = null;

function auditLabel(english, japanese) {
  return currentLang === 'en' ? english : japanese;
}

function auditDate(value) {
  if (!value) return auditLabel('Unavailable', '未取得');
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return auditLabel('Unavailable', '未取得');
  return date.toLocaleString(currentLang === 'en' ? 'en' : 'ja', {dateStyle: 'medium', timeStyle: 'short'});
}

async function auditRequest(action, context) {
  const response = await fetch('/api/audit/' + action, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(context)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || auditLabel('Request failed', '取得に失敗しました'));
  return result;
}

function auditLink(url, title) {
  return `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(title)} ↗</a>`;
}

function repositoryFacts(info) {
  const root = info.repository_url;
  return `<div>${auditLabel('Latest branch commit', '最新ブランチのコミット')}:
    <code>${escapeHtml(info.branch)}</code> ${auditLink(root + '/commit/' + info.head, info.head.slice(0, 7))}
    · ${auditDate(info.head_date)}</div>
    <div>${auditLabel('Repository last pushed', 'リポジトリの最終 Push')}: ${auditDate(info.pushed_at)}</div>
    <div>${auditLabel('Checked', '取得日時')}: ${auditDate(info.checked_at)}</div>`;
}

async function updateAuditRepositoryStatus(hero, repo, force = false) {
  if (!document.documentElement.classList.contains('native-host') || repo.is_root) return;
  const target = hero.querySelector('[data-audit-repository-status]');
  if (!target) return;
  const key = String(repo.id);
  if (force || !auditRepositoryStatuses.has(key)) {
    const entry = auditRequest('evidence', {repository: key});
    auditRepositoryStatuses.set(key, entry);
    entry.catch(() => {
      if (auditRepositoryStatuses.get(key) === entry) auditRepositoryStatuses.delete(key);
    });
  }
  target.textContent = auditLabel('Checking GitHub…', 'GitHub を確認中…');
  try {
    const info = await auditRepositoryStatuses.get(key);
    target.innerHTML = repositoryFacts(info);
  } catch (error) {
    target.textContent = auditLabel('Latest GitHub status unavailable', 'GitHub の最新情報を取得できません');
  }
  const retry = document.createElement('button');
  retry.type = 'button';
  retry.className = 'table-view-btn';
  retry.textContent = auditLabel('Refresh GitHub status', 'GitHub の情報を更新');
  retry.onclick = () => updateAuditRepositoryStatus(hero, repo, true);
  target.append(retry);
}

function findingSourceControls(repo, issue, file) {
  if (!document.documentElement.classList.contains('native-host')) return '';
  const location = String(file).match(/^(.+?):(\d+)(?:\s|$)/);
  if (!location) return '';
  const context = {
    repository: String(repo.id), path: location[1], line: Number(location[2]),
    legacy_password_alert: String(issue.title).includes('Database / Hardcoded Password')
      && String(issue.title).includes('シークレット漏洩検知')
  };
  return `<div class="finding-source" data-context="${escapeHtml(JSON.stringify(context))}">
    <div class="issue-actions">
      <button type="button" class="table-view-btn" data-load-finding-source onclick="loadFindingSource(this)">
        ${auditLabel('Compare current source', '現在のソースを照合')}</button>
      <button type="button" class="table-view-btn" onclick="chatAboutFinding(this)">
        ${auditLabel('Ask AI about this finding', 'この指摘をAIに相談')}</button>
    </div>
    <div data-evidence-result aria-live="polite"></div>
  </div>`;
}

function sourceComparison(info) {
  if (!info.path) return '';
  const root = info.repository_url;
  const fileURL = sha => root + '/blob/' + sha + '/' + info.path.split('/').map(encodeURIComponent).join('/');
  const source = (title, sha, line, error) => `<div class="audit-source-version">
    <h3>${title} ${sha ? auditLink(fileURL(sha) + (line ? '#L' + line.number : ''), sha.slice(0, 7)) : ''}</h3>
    ${line ? `<pre>${line.number}  ${escapeHtml(line.text)}</pre>` : `<p>
      ${escapeHtml(error || auditLabel('No reliable line match. Open the file to inspect it.', '該当行を特定できません。リンクからファイルを確認してください。'))}</p>`}
  </div>`;
  const change = info.last_file_change;
  const currentTitle = info.current_line_at_old_number
    ? auditLabel('Current source at the same line number (match unverified)', '現在の同じ行番号のソース（対応は未確認）')
    : auditLabel('Current source', '現在のソース');
  const status = info.false_positive
    ? auditLabel('False positive at the audited commit: this line is a Secrets Manager ARN reference.', '監査時点の誤検知です。この行は Secrets Manager の ARN 参照です。')
    : info.audited_line && info.current_line
      ? (info.line_comparison === 'identical'
        ? auditLabel('The matched lines are identical.', '照合した行の内容は同じです。')
        : auditLabel('Review the two versions below for changes.', '以下の両時点の内容を確認してください。'))
      : '';
  return `<div class="audit-comparison">
    ${repositoryFacts(info)}
    <div>${auditLabel('File last changed', 'ファイルの最終変更')}:
      ${change ? auditDate(change.date) + ' · ' + auditLink(root + '/commit/' + change.sha, change.sha.slice(0, 7)) : auditLabel('Unavailable', '未取得')}</div>
    ${status ? `<p class="audit-comparison-status">${status}</p>` : ''}
    ${source(auditLabel('Audited source', '監査時のソース'), info.saved_sha, info.audited_line, info.saved_error)}
    ${source(currentTitle, info.head, info.current_line || info.current_line_at_old_number, info.current_error)}
  </div>`;
}

async function loadFindingSource(button) {
  const panel = button.closest('.finding-source');
  const result = panel.querySelector('[data-evidence-result]');
  button.disabled = true;
  result.textContent = auditLabel('Comparing GitHub commits…', 'GitHub のコミットを照合中…');
  try {
    const info = await auditRequest('evidence', JSON.parse(panel.dataset.context));
    result.innerHTML = sourceComparison(info);
    if (info.false_positive) {
      panel.parentElement.querySelector('.saved-finding-description').hidden = true;
      const summary = panel.closest('.audit-issue').querySelector('summary');
      summary.querySelector('.issue-severity').textContent = auditLabel('False positive', '誤検知');
      summary.querySelector('.issue-severity').className = 'issue-severity info';
      summary.querySelector('.issue-title').textContent = auditLabel('Secrets Manager reference', 'Secrets Manager の参照');
    }
  } catch (error) {
    result.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

function auditChatVisible() {
  return Boolean(document.getElementById('audit-chat'));
}

function closeAuditChat() {
  document.getElementById('audit-chat')?.remove();
  document.getElementById('app-workspace')?.removeAttribute('inert');
}

function openAuditChat(context = null) {
  const id = String(selectedDiagram?.id || '');
  if (!auditConversation || auditConversation.repository !== id || context) {
    auditConversation = {repository: id, context, messages: [], pending: false, draft: '', path: '', line: ''};
  }
  renderAuditChat();
}

function chatAboutFinding(button) {
  const context = JSON.parse(button.closest('.finding-source').dataset.context);
  openAuditChat(context);
  publishNativeWorkspace('chat');
}

function renderAuditChat() {
  const state = auditConversation;
  if (!state) return;
  let section = document.getElementById('audit-chat');
  if (!section) {
    section = document.createElement('section');
    section.id = 'audit-chat';
    document.body.append(section);
    document.getElementById('app-workspace')?.setAttribute('inert', '');
  }
  const context = state.context;
  section.innerHTML = `<div class="audit-chat-inner">
    <header><h2>${auditLabel('Audit chat', '監査チャット')}</h2>
      <p>${escapeHtml(selectedDiagram?.is_root ? '' : (selectedDiagram?.repo || ''))}</p>
    </header>
    ${!selectedDiagram || selectedDiagram.is_root ? `<p>${auditLabel('Select a saved repository from the sidebar.', 'サイドバーから保存済みのリポジトリを選択してください。')}</p>` : `
    ${context ? `<code>${escapeHtml(context.path)}:${context.line}</code>` : `
      <div class="audit-chat-location">
        <label>${auditLabel('File path (optional)', 'ファイルパス（任意）')}
          <input name="path" placeholder="src/main.py" maxlength="500" value="${escapeHtml(state.path)}"></label>
        <label>${auditLabel('Audit line', '監査時の行番号')}
          <input name="line" type="number" min="1" max="1000000" value="${escapeHtml(state.line)}"></label>
      </div>`}
    <div class="audit-chat-messages" aria-live="polite">
      ${state.latest ? `<details><summary>${auditLabel('Latest GitHub evidence', '最新のGitHub確認結果')}</summary>
        ${state.latest.path ? sourceComparison(state.latest) : repositoryFacts(state.latest)}</details>` : ''}
      ${state.messages.map(message => `<article>
        <strong>${message.role === 'user' ? auditLabel('You', 'あなた') : 'AI'}</strong>
        <p>${escapeHtml(message.text)}</p>
      </article>`).join('')}
      ${state.pending ? `<p role="status">${auditLabel('Checking GitHub and waiting for AI…', 'GitHub を確認し、AI の回答を待っています…')}</p>` : ''}
      ${state.error ? `<p class="audit-chat-error" role="alert">${escapeHtml(state.error)}</p>` : ''}
    </div>
    <form>
      <label for="audit-question">${auditLabel('Question', '質問')}</label>
      <textarea id="audit-question" required maxlength="4000" rows="3" placeholder="${auditLabel('What changed since the audit?', '監査時点から何が変わった？')}">${escapeHtml(state.draft)}</textarea>
      <div class="issue-actions">
        <button class="table-view-btn workspace-primary" type="submit" ${state.pending ? 'disabled' : ''}>${auditLabel('Check GitHub and ask AI', 'GitHubを確認してAIに聞く')}</button>
      </div>
      <p class="audit-note">${auditLabel('Your question, recent conversation and evidence metadata are sent to the configured AI provider.', '質問・直近の会話・監査の比較結果を設定済みAIに送ります。')}</p>
    </form>`}
  </div>`;
  const input = section.querySelector('textarea');
  if (!input) return;
  input.oninput = () => { state.draft = input.value; };
  for (const field of section.querySelectorAll('.audit-chat-location input')) {
    field.oninput = () => { state[field.name] = field.value; };
  }
  section.querySelector('form').onsubmit = event => {
    event.preventDefault();
    sendAuditQuestion(state);
  };
  const messages = section.querySelector('.audit-chat-messages');
  messages.scrollTop = messages.scrollHeight;
}

async function sendAuditQuestion(state) {
  if (state.pending || !state.draft.trim()) return;
  const location = state.context || (state.path.trim() ? {path: state.path.trim(), line: Number(state.line)} : {});
  if (location.path && (!Number.isInteger(location.line) || location.line < 1 || location.line > 1000000)) {
    state.error = auditLabel('Enter the audited line number.', '監査時の行番号を入力してください。');
    renderAuditChat();
    return;
  }
  const history = state.messages.slice(-6).map(({role, text}) => ({role, text: text.slice(0, 4000)}));
  const question = state.draft.trim();
  state.pending = true;
  state.error = '';
  state.draft = '';
  state.messages.push({role: 'user', text: question});
  renderAuditChat();
  try {
    const response = await auditRequest('chat', {
      repository: state.repository, ...location, question, history, language: currentLang
    });
    state.latest = response;
    if (response.answer) state.messages.push({role: 'assistant', text: response.answer});
    else state.error = response.ai_error;
  } catch (error) {
    state.error = error.message;
    if (!state.draft) state.draft = question;
    state.messages.pop();
  } finally {
    state.pending = false;
    if (auditConversation === state && auditChatVisible()) renderAuditChat();
  }
}
