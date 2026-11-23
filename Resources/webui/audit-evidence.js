/* Read-only GitHub evidence and contextual conversation in the native workspace. */
const auditRepositoryStatuses = new Map();
const AUDIT_CONVERSATIONS_STORAGE_KEY = 'repoaudt_audit_conversations_v1';
let auditConversation = null;
let auditConversations = loadAuditConversations();
let auditLLMConfig = null;

function loadAuditConversations() {
  try {
    const raw = localStorage.getItem(AUDIT_CONVERSATIONS_STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return [];
  }
}

function saveAuditConversations() {
  if (!auditConversation || !auditConversation.id) return;
  auditConversation.updatedAt = new Date().toISOString();
  const idx = auditConversations.findIndex(c => c.id === auditConversation.id);
  const snapshot = {
    ...auditConversation,
    pending: false
  };
  if (idx >= 0) {
    auditConversations[idx] = snapshot;
  } else {
    auditConversations.unshift(snapshot);
  }
  auditConversations.sort((a, b) => String(b.updatedAt || '').localeCompare(String(a.updatedAt || '')));
  if (auditConversations.length > 50) auditConversations.length = 50;
  try {
    localStorage.setItem(AUDIT_CONVERSATIONS_STORAGE_KEY, JSON.stringify(auditConversations));
  } catch (_) {}
}

function buildConversationTitle(repo, context) {
  const repoName = repo?.is_root ? '' : (repo?.repo || '');
  if (context && context.title) {
    return context.title;
  }
  if (context && context.path) {
    return `${context.path}${context.line ? ':' + context.line : ''}`;
  }
  return repoName || auditLabel('Repository Audit Chat', 'リポジトリ監査チャット');
}

const AUDIT_PROVIDER_LABELS = {
  openai: 'OpenAI',
  claude: 'Claude',
  gemini: 'Gemini',
  groq: 'Groq',
  copilot: 'GitHub Copilot',
  local: 'Local LLM'
};

async function loadAuditLLMConfig(force = false) {
  if (auditLLMConfig && !force) return auditLLMConfig;
  try {
    const resp = await fetch('/api/settings');
    if (resp.ok) {
      auditLLMConfig = await resp.json();
    }
  } catch (_) {}
  return auditLLMConfig;
}

function getConfiguredAuditProviders(cfg) {
  if (!cfg || !cfg.configured) return [];
  return Object.keys(AUDIT_PROVIDER_LABELS).filter(key => Boolean(cfg.configured[key]));
}

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
  if (info.latest_unavailable) {
    return `<p>${auditLabel('Latest GitHub status unavailable', 'GitHub の最新情報を取得できません')}</p>`;
  }
  const root = info.repository_url;
  return `<div>${auditLabel('Latest branch commit', '最新ブランチのコミット')}:
    <code>${escapeHtml(info.branch)}</code> ${auditLink(root + '/commit/' + info.head, info.head.slice(0, 7))}
    · ${auditDate(info.head_date)}</div>
    <div>${auditLabel('Repository last pushed', 'リポジトリの最終 Push')}: ${auditDate(info.pushed_at)}</div>
    <div>${auditLabel('Checked', '取得日時')}: ${auditDate(info.checked_at)}</div>`;
}

function pullRequestControl(repo) {
  if (!document.documentElement.classList.contains('native-host') || repo.is_root ||
      !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/.test(repo.github_url || '')) return '';
  return `<details class="audit-comparison">
    <summary>${auditLabel('Pull request status', 'PRの進捗')}</summary>
    <form class="issue-actions" data-repository="${escapeHtml(String(repo.id))}"
      onsubmit="event.preventDefault(); loadPullRequestStatus(this)">
      <label>${auditLabel('PR number or GitHub URL', 'PR番号またはGitHub URL')}
        <input name="pull" type="text" maxlength="240" required>
      </label>
      <button type="submit" class="table-view-btn">${auditLabel('Check status', '状態を確認')}</button>
    </form>
    <div data-pull-status role="status"></div>
  </details>`;
}

async function loadPullRequestStatus(form) {
  const output = form.parentElement.querySelector('[data-pull-status]');
  const button = form.querySelector('button');
  button.disabled = true;
  output.textContent = auditLabel('Checking GitHub…', 'GitHubを確認中…');
  try {
    const info = await auditRequest('pull-request', {
      repository: form.dataset.repository, pull: form.elements.pull.value.trim()
    });
    const states = {
      open: auditLabel('Open', '進行中'),
      draft: auditLabel('Draft', '下書き'),
      closed: auditLabel('Closed', 'クローズ済み'),
      merged: auditLabel('Merged', 'マージ済み')
    };
    const head = info.head_repository || auditLabel('Source repository unavailable', '変更元のリポジトリを取得できません');
    const branch = (repo, ref) => escapeHtml(repo + ':' + ref);
    const merge = info.merge_commit
      ? `<p>${auditLabel('Integrated commit for re-audit', '再監査に使う取り込みコミット')}
        ${auditLink('https://github.com/' + info.base_repository + '/commit/' + info.merge_commit, info.merge_commit.slice(0, 9))}
        <button type="button" class="table-view-btn" onclick="copyCmdFromButton(this)" data-cmd="${escapeHtml(info.merge_commit)}">
          ${auditLabel('Copy SHA', 'SHAをコピー')}
        </button></p>` : '';
    output.innerHTML = `<p>${auditLink(info.url, '#' + info.number)} · ${states[info.status]}
      · ${auditDate(info.merged_at || info.updated_at)}</p>
      <p><code>${branch(head, info.head_ref)} → ${branch(info.base_repository, info.base_ref)}</code></p>${merge}`;
  } catch (error) {
    output.textContent = auditLabel('PR status unavailable: ', 'PRの状態を取得できません：') + error.message;
  } finally {
    button.disabled = false;
  }
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

function recordedAuthorizationChain(repo, issue) {
  const revision = repo.source_revision;
  const root = String(repo.github_url || '');
  if (issue.scanner !== 'authorization-evidence' ||
      revision?.kind !== 'github_commit' || repo.commit_hash !== revision.commit_sha ||
      !/^[0-9a-f]{40}$/.test(revision.commit_sha) ||
      !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(root)) return '';
  const labels = {
    entry: auditLabel('Entry point', '入口'),
    boundary: auditLabel('Authorization boundary', '認可境界'),
    input: auditLabel('Request input', 'リクエスト入力'),
    privileged_effect: auditLabel('Privileged operation', '高権限処理')
  };
  const rows = (issue.evidence_chain || []).filter(step =>
    Object.hasOwn(labels, step.kind) && step.commit === revision.commit_sha &&
    typeof step.file === 'string' && Number.isInteger(step.line) && step.line > 0 &&
    typeof step.source === 'string'
  );
  if (!rows.length) return '';
  return `<div class="audit-comparison" aria-label="${auditLabel('Recorded evidence', '保存済みのコード根拠')}">
    <h3>${auditLabel('Recorded evidence', '保存済みのコード根拠')} · <code>${revision.commit_sha.slice(0, 9)}</code></h3>
    ${rows.map(step => {
      const pathname = step.file.split('/').map(encodeURIComponent).join('/');
      const url = root + '/blob/' + revision.commit_sha + '/' + pathname + '#L' + step.line;
      return `<div class="audit-source-version">
        <h3>${labels[step.kind]} · ${auditLink(url, step.file + ':' + step.line)}</h3>
        <pre>${step.line}  ${escapeHtml(step.source)}</pre>
      </div>`;
    }).join('')}
  </div>`;
}


function disclosureDraft(repo, issue) {
  const revision = repo.source_revision;
  const finding = String(issue.file).match(/^([A-Za-z0-9_./-]+\.py):([1-9][0-9]{0,6})$/);
  if (issue.scanner !== 'authorization-evidence' ||
      issue.id !== 'CWE-862-python-local-privileged-route' ||
      revision?.kind !== 'github_commit' ||
      !/^[0-9a-f]{40}$/.test(revision.commit_sha) || repo.commit_hash !== revision.commit_sha ||
      !/^[A-Za-z0-9][A-Za-z0-9-]*\/(?!\.{1,2}$)[A-Za-z0-9_.-]+$/.test(revision.repository) ||
      !finding || finding[1].split('/').some(part => !part || part === '.' || part === '..' || part === '.git')) {
    return null;
  }
  const root = 'https://github.com/' + revision.repository;
  const path = finding[1].split('/').map(encodeURIComponent).join('/');
  const location = root + '/blob/' + revision.commit_sha + '/' + path + '#L' + finding[2];
  const lines = [
    auditLabel('# Private disclosure draft', '# 非公開報告用の下書き'),
    '',
    auditLabel('## Summary', '## 概要'),
    auditLabel('CWE-862. Caller authorization is missing on a local API path to a privileged operation.', 'CWE-862。高権限処理につながるローカルAPIの経路で、呼び出し元の認可が確認できません。'),
    '',
    auditLabel('## Audited revision and location', '## 監査対象のコミットと箇所'),
    '- ' + revision.repository + ' @ ' + revision.commit_sha,
    '- ' + location,
    '',
    auditLabel('## Impact and verification scope', '## 影響と確認範囲'),
    auditLabel('Static review identified a path to privileged processing in this revision. Runtime behavior, affected releases and actual impact require confirmation.', 'このコミットの静的監査で高権限処理への経路を確認しました。稼働時の挙動、影響を受けるリリース、実際の影響は別途確認が必要です。'),
    '',
    auditLabel('## Suggested remediation', '## 修正案'),
    auditLabel('Remove the route if it is unnecessary. If it is required, authenticate the caller and enforce authorization before privileged processing.', '不要な経路は廃止してください。必要な場合は呼び出し元を認証し、高権限処理の前に認可を検証してください。'),
  ];
  return {text: lines.join('\n'), policy: root + '/security/policy'};
}

function disclosureEditor(repo, issue) {
  const draft = disclosureDraft(repo, issue);
  if (!draft) return '';
  const title = auditLabel('Private disclosure draft', '非公開報告の下書き');
  return `<details class="audit-comparison audit-disclosure">
    <summary>${title}</summary>
    <p>${auditLabel('Review this local draft and use the repository’s security policy to find its private reporting channel.', '下書きの内容を確認し、報告先はリポジトリのセキュリティポリシーで確認してください。')}</p>
    <textarea rows="10" spellcheck="false" aria-label="${title}">${escapeHtml(draft.text)}</textarea>
    <div class="issue-actions">
      <button type="button" class="table-view-btn" onclick="copyDisclosureDraft(this)">${auditLabel('Copy draft', '下書きをコピー')}</button>
      ${auditLink(draft.policy, auditLabel('Security policy', 'セキュリティポリシー'))}
      <span role="status"></span>
    </div>
  </details>`;
}

async function copyDisclosureDraft(button) {
  const editor = button.closest('.audit-disclosure');
  const status = editor.querySelector('[role="status"]');
  try {
    await navigator.clipboard.writeText(editor.querySelector('textarea').value);
    status.textContent = auditLabel('Copied', 'コピーしました');
  } catch (_) {
    status.textContent = auditLabel('Copy failed. Select the draft to copy it manually.', 'コピーできませんでした。下書きの本文を選択してコピーしてください。');
  }
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
  const canVerify = issue.scanner === 'authorization-evidence' && issue.diff
    && repo.source_revision?.kind === 'github_commit';
  const canCopilotIssue = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/.test(repo.github_url || '');
  return `<div class="finding-source" data-context="${escapeHtml(JSON.stringify(context))}" data-finding-title="${escapeHtml(String(issue.title || ''))}" data-finding-severity="${escapeHtml(String(issue.severity || ''))}" data-finding-desc="${escapeHtml(String(issue.description || issue.fix || ''))}">
    <div class="issue-actions">
      <button type="button" class="table-view-btn" data-load-finding-source onclick="loadFindingSource(this)">
        ${auditLabel('Compare current source', '現在のソースを照合')}</button>
      <button type="button" class="table-view-btn" onclick="chatAboutFinding(this)">
        ${auditLabel('Ask AI about this finding', 'この指摘をAIに相談')}</button>
      ${canCopilotIssue
        ? `<button type="button" class="table-view-btn" onclick="createCopilotIssueForFinding(this)">
          ${auditLabel('Assign to Copilot', 'Copilot に修正 Issue を依頼')}</button>` : ''}
      ${canVerify
        ? `<button type="button" class="table-view-btn" onclick="verifyFindingDiff(this)">
          ${auditLabel('Verify diff locally', '修正差分をローカル検証')}</button>` : ''}
    </div>
    <div data-copilot-issue role="status"></div>
    <div data-diff-verification role="status"></div>
    ${canVerify ? `<form class="issue-actions" onsubmit="event.preventDefault(); verifyRemediationCommit(this)">
      <label>${auditLabel('Remediation commit SHA', '修正コミットのSHA')}
        <input name="commit" type="text" pattern="[0-9a-fA-F]{40}" maxlength="40"
          autocomplete="off" spellcheck="false" size="22" required>
      </label>
      <button type="submit" class="table-view-btn">${auditLabel('Check commit locally', '修正コミットを再監査')}</button>
      <div role="status" data-commit-verification></div>
    </form>` : ''}
    ${recordedAuthorizationChain(repo, issue)}
    ${disclosureEditor(repo, issue)}
    <div data-evidence-result aria-live="polite"></div>
  </div>`;
}

async function createCopilotIssueForFinding(button) {
  const panel = button.closest('.finding-source');
  const output = panel.querySelector('[data-copilot-issue]');
  const {repository, path, line} = JSON.parse(panel.dataset.context);
  const findingTitle = panel.dataset.findingTitle || 'Security/Audit Finding';
  const severity = panel.dataset.findingSeverity || 'medium';
  const desc = panel.dataset.findingDesc || '';
  const title = `[RepoAUDT] Fix ${findingTitle} (${path}:${line})`;
  const body = [
    `## Audit Finding`,
    `- **Title**: ${findingTitle}`,
    `- **Severity**: ${severity}`,
    `- **Location**: \`${path}:${line}\``,
    desc ? `\n## Details\n${desc}` : '',
    `\n## Request\nPlease investigate and open a PR to fix this issue safely.`
  ].filter(Boolean).join('\n');

  button.disabled = true;
  output.textContent = auditLabel('Creating GitHub Issue for Copilot…', 'Copilot 用 GitHub Issue を作成中…');
  try {
    const result = await auditRequest('copilot-issue', {
      repository, title, body, assign_copilot: true
    });
    const badge = result.copilot_assigned
      ? auditLabel('Assigned to @copilot', '@copilot にアサイン済み')
      : auditLabel('Issue created (assign @copilot manually if needed)', 'Issue を作成しました（必要に応じて @copilot をアサインしてください）');
    output.innerHTML = `${auditLink(result.issue_url, '#' + (result.issue_number || 'Issue'))} · ${escapeHtml(badge)}`;
  } catch (error) {
    output.textContent = auditLabel('Failed to create Issue: ', 'Issue 作成に失敗：') + error.message;
  } finally {
    button.disabled = false;
  }
}

async function verifyRemediationCommit(form) {
  const {repository, path, line} = JSON.parse(form.closest('.finding-source').dataset.context);
  const output = form.querySelector('[data-commit-verification]');
  const button = form.querySelector('button');
  const compare_commit = form.elements.commit.value.toLowerCase();
  button.disabled = true;
  output.textContent = auditLabel('Checking the selected local commit…', '指定コミットをローカルで確認中…');
  try {
    const result = await auditRequest('verify-diff', {repository, path, line, compare_commit});
    const status = result.after === 'not_detected'
      ? auditLabel('The same static rule no longer detects this finding.', '同じ静的ルールではこの指摘を検出しません。')
      : auditLabel('The same static rule still detects this finding.', '同じ静的ルールで引き続き検出しました。');
    const commitLink = sha => auditLink(result.repository_url + '/commit/' + sha, sha.slice(0, 9));
    output.innerHTML = `${commitLink(result.audited_commit)} → ${commitLink(result.commit)} · ${auditLabel('Local Git objects', 'ローカルのGitオブジェクト')} · ${status}`;
  } catch (error) {
    output.textContent = auditLabel('Check unavailable: ', '再監査できません：') + error.message;
  } finally {
    button.disabled = false;
  }
}

async function verifyFindingDiff(button) {
  const panel = button.closest('.finding-source');
  const output = panel.querySelector('[data-diff-verification]');
  const {repository, path, line} = JSON.parse(panel.dataset.context);
  button.disabled = true;
  output.textContent = auditLabel('Verifying in a disposable copy…', '隔離コピーで検証中…');
  try {
    const result = await auditRequest('verify-diff', {repository, path, line});
    const outcome = result.after === 'not_detected'
      ? auditLabel('Before: detected. After: not detected by the same static rule.', '適用前：検出。適用後：同じ静的ルールでは未検出。')
      : auditLabel('Before: detected. After: still detected.', '適用前：検出。適用後：引き続き検出。');
    const source = result.source === 'local_git'
      ? auditLabel('Local Git object', 'ローカルのGitオブジェクト')
      : auditLabel('Verified GitHub checkout', '検証済みのGitHubコピー');
    output.textContent = outcome + ' ' + source + ' · ' + result.commit.slice(0, 9);
  } catch (error) {
    output.textContent = auditLabel('Verification unavailable: ', '検証未実施：') + error.message;
  } finally {
    button.disabled = false;
  }
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
    ${source(info.audited_source === 'recorded'
      ? auditLabel('Audited source (saved)', '監査時のソース（保存済み）')
      : auditLabel('Audited source', '監査時のソース'), info.saved_sha, info.audited_line, info.saved_error)}
    ${source(currentTitle, info.head, info.current_line || info.current_line_at_old_number, info.current_error)}
  </div>`;
}

function openNativeOrSettingsPage(targetPage) {
  if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.navigate) {
    window.webkit.messageHandlers.navigate.postMessage({page: targetPage});
    return;
  }
  if (typeof openSettingsModal === 'function') {
    openSettingsModal();
  }
}

function renderEvidenceErrorBanner(resultEl, errorMessage, retryFn) {
  const msg = String(errorMessage || 'Unknown error');
  const isGhConnectError = /github|gh\b|connect|auth|token|resolve|certificate|signed in|installed|permission/i.test(msg);
  const heading = isGhConnectError
    ? auditLabel('GitHub CLI could not connect to GitHub', 'GitHub CLI が GitHub に接続できません')
    : auditLabel('Re-scan failed', '再スキャンに失敗しました');
  const guidance = isGhConnectError
    ? auditLabel(
        'Check your network/VPN or GitHub CLI (`gh auth login`) and GitHub Token settings.',
        'ネットワーク接続・GitHub CLI（gh auth login）または GitHub トークン設定を確認してください。'
      )
    : '';

  resultEl.innerHTML = '';
  const box = document.createElement('div');
  box.setAttribute('role', 'alert');
  Object.assign(box.style, {
    marginTop: '10px',
    padding: '12px 14px',
    borderRadius: '8px',
    border: '1px solid rgba(248, 113, 113, 0.55)',
    background: 'rgba(127, 29, 29, 0.28)',
    color: '#fecaca',
    display: 'flex',
    flexDirection: 'column',
    gap: '8px'
  });

  const titleEl = document.createElement('div');
  titleEl.style.fontWeight = '700';
  titleEl.style.fontSize = '0.9rem';
  titleEl.style.color = '#fca5a5';
  titleEl.textContent = `⚠️ ${heading}`;
  box.appendChild(titleEl);

  const detailEl = document.createElement('div');
  detailEl.style.fontSize = '0.82rem';
  detailEl.style.color = '#fee2e2';
  detailEl.textContent = guidance ? `${msg} — ${guidance}` : msg;
  box.appendChild(detailEl);

  const actions = document.createElement('div');
  actions.style.display = 'flex';
  actions.style.flexWrap = 'wrap';
  actions.style.gap = '8px';

  if (isGhConnectError) {
    const connectBtn = document.createElement('button');
    connectBtn.type = 'button';
    connectBtn.textContent = auditLabel('🔗 Open GitHub / AI Connection', '🔗 GitHub / AI 接続設定を開く');
    Object.assign(connectBtn.style, {
      padding: '6px 12px',
      borderRadius: '6px',
      border: '1px solid rgba(96, 165, 250, 0.65)',
      background: 'rgba(37, 99, 235, 0.35)',
      color: '#eff6ff',
      fontSize: '0.8rem',
      fontWeight: '600',
      cursor: 'pointer'
    });
    connectBtn.addEventListener('click', () => openNativeOrSettingsPage('ai'));
    actions.appendChild(connectBtn);

    const sysBtn = document.createElement('button');
    sysBtn.type = 'button';
    sysBtn.textContent = auditLabel('⚙️ Check GitHub CLI Status', '⚙️ 実行環境・GitHub CLI を確認');
    Object.assign(sysBtn.style, {
      padding: '6px 12px',
      borderRadius: '6px',
      border: '1px solid rgba(148, 163, 184, 0.45)',
      background: 'rgba(30, 41, 59, 0.7)',
      color: '#e2e8f0',
      fontSize: '0.8rem',
      cursor: 'pointer'
    });
    sysBtn.addEventListener('click', () => openNativeOrSettingsPage('system'));
    actions.appendChild(sysBtn);
  }

  if (typeof retryFn === 'function') {
    const retryBtn = document.createElement('button');
    retryBtn.type = 'button';
    retryBtn.textContent = auditLabel('🔄 Retry', '🔄 再試行');
    Object.assign(retryBtn.style, {
      padding: '6px 12px',
      borderRadius: '6px',
      border: '1px solid rgba(255, 255, 255, 0.2)',
      background: 'rgba(255, 255, 255, 0.08)',
      color: '#f8fafc',
      fontSize: '0.8rem',
      cursor: 'pointer'
    });
    retryBtn.addEventListener('click', retryFn);
    actions.appendChild(retryBtn);
  }

  box.appendChild(actions);
  resultEl.appendChild(box);
}

function setIssueRescanSpinning(issueEl, spinning) {
  if (!issueEl) return;
  const summary = issueEl.querySelector('summary');
  if (!summary) return;
  summary.querySelector('.finding-rescan-spinner')?.remove();
  if (spinning) {
    const spinner = document.createElement('span');
    spinner.className = 'audit-spinner finding-rescan-spinner';
    spinner.setAttribute('aria-hidden', 'true');
    spinner.style.marginLeft = '8px';
    spinner.style.flexShrink = '0';
    const chevron = summary.querySelector('.issue-chevron');
    if (chevron) {
      summary.insertBefore(spinner, chevron);
    } else {
      summary.appendChild(spinner);
    }
  }
}

async function loadFindingSource(button) {
  const panel = button.closest('.finding-source');
  const issueEl = button.closest('.audit-issue');
  const result = panel.querySelector('[data-evidence-result]');
  const origHtml = button.innerHTML;
  button.disabled = true;
  button.innerHTML = `<span style="display:inline-flex;align-items:center;gap:6px;"><span class="audit-spinner" aria-hidden="true"></span><span>${auditLabel('Re-scanning…', '再スキャン中…')}</span></span>`;
  setIssueRescanSpinning(issueEl, true);
  result.innerHTML = `<p class="audit-chat-pending" role="status"><span class="audit-spinner" aria-hidden="true"></span><span>${auditLabel('Comparing GitHub commits…', 'GitHub のコミットを照合中…')}</span></p>`;
  try {
    const info = await auditRequest('evidence', JSON.parse(panel.dataset.context));
    result.innerHTML = sourceComparison(info);
    if (info.false_positive) {
      panel.parentElement.querySelector('.saved-finding-description').hidden = true;
      const summary = issueEl.querySelector('summary');
      summary.querySelector('.issue-severity').textContent = auditLabel('False positive', '誤検知');
      summary.querySelector('.issue-severity').className = 'issue-severity info';
      summary.querySelector('.issue-title').textContent = auditLabel('Secrets Manager reference', 'Secrets Manager の参照');
    }
  } catch (error) {
    renderEvidenceErrorBanner(result, error.message, () => loadFindingSource(button));
  } finally {
    button.disabled = false;
    button.innerHTML = origHtml;
    setIssueRescanSpinning(issueEl, false);
  }
}

function auditChatVisible() {
  return Boolean(document.getElementById('audit-chat'));
}

function closeAuditChat() {
  document.getElementById('audit-chat')?.remove();
  document.getElementById('app-workspace')?.removeAttribute('inert');
}

function jumpToAuditRepoPage(repoId, findingTitle = '') {
  if (typeof diagrams !== 'undefined' && Array.isArray(diagrams) && repoId) {
    const idx = diagrams.findIndex(d => String(d.id) === String(repoId));
    if (idx >= 0 && typeof selectDiagram === 'function' && String(selectedDiagram?.id || '') !== String(repoId)) {
      selectDiagram(idx);
    }
  }
  closeAuditChat();
  if (typeof switchViewMode === 'function') {
    switchViewMode('coderabbit');
  }
  publishNativeWorkspace('coderabbit');

  if (findingTitle) {
    setTimeout(() => {
      const targetNorm = findingTitle.trim().toLowerCase();
      const issues = Array.from(document.querySelectorAll('.audit-issue'));
      const match = issues.find(el => {
        const t = (el.querySelector('.issue-title')?.textContent || '').trim().toLowerCase();
        return t === targetNorm || (targetNorm && t.includes(targetNorm));
      });
      if (match) {
        match.open = true;
        match.scrollIntoView({behavior: 'smooth', block: 'center'});
      }
    }, 80);
  }
}

function buildAuditStarter(repo, context) {
  if (!repo || repo.is_root) return {greeting: '', greetingHtml: '', suggestions: []};
  const issues = typeof getWorkspaceIssues === 'function' ? getWorkspaceIssues(repo) : [];
  const repoId = String(repo.id || '');
  const repoBtn = `<button type="button" class="table-view-btn" style="padding: 2px 8px; font-size: 0.85rem;" data-jump-repo="${escapeHtml(repoId)}">${escapeHtml(repo.repo)}</button>`;

  if (context && (context.title || context.path)) {
    const sev = context.severity ? `[${String(context.severity).toUpperCase()}] ` : '';
    const loc = context.path ? `${context.path}${context.line ? ':' + context.line : ''}` : '';
    const desc = context.desc ? `\n${context.desc}` : '';
    const findingName = context.title || loc || '';
    const greeting = auditLabel(
      `Loaded finding for ${repo.repo}:\n${sev}${findingName}${loc && context.title ? ' (' + loc + ')' : ''}${desc}\n\nWhat would you like to do with this finding?`,
      `「${repo.repo}」の指摘を読み込みました：\n${sev}${findingName}${loc && context.title ? ' (' + loc + ')' : ''}${desc}\n\nこの指摘について何をしますか？`
    );
    const findingLink = `<button type="button" class="table-view-btn" style="text-align: left; white-space: normal; padding: 4px 8px;" data-jump-repo="${escapeHtml(repoId)}" data-jump-finding="${escapeHtml(context.title || '')}">${escapeHtml(sev + findingName)}${loc && context.title ? ` <code>${escapeHtml(loc)}</code>` : ''}</button>`;
    const greetingHtml = `
      <div>${repoBtn} ${auditLabel('— Loaded finding:', 'の指摘を読み込みました：')}</div>
      <div style="margin: 6px 0;">${findingLink}</div>
      ${context.desc ? `<div style="color: var(--workspace-muted); white-space: pre-wrap; margin-bottom: 6px;">${escapeHtml(context.desc)}</div>` : ''}
      <div>${auditLabel('What would you like to do with this finding?', 'この指摘について何をしますか？')}</div>
    `;
    const targetLabel = context.title || loc || 'this finding';
    return {
      greeting,
      greetingHtml,
      suggestions: [
        {
          label: auditLabel('🛠️ Propose a safe code fix', '🛠️ 安全な修正案を提案して'),
          prompt: auditLabel(
            `Propose a concrete, defensive code fix for "${targetLabel}"${loc ? ' at ' + loc : ''}.`,
            `「${targetLabel}」${loc ? '（' + loc + '）' : ''}に対する具体的で安全な修正案（コード例）を提案してください。`
          )
        },
        {
          label: auditLabel('🔎 Check if still present on GitHub', '🔎 最新コードでまだ発生しているか確認'),
          prompt: auditLabel(
            `Check the latest GitHub commit for "${targetLabel}"${loc ? ' at ' + loc : ''} and tell me if it is still present.`,
            `最新の GitHub コミットを確認して、「${targetLabel}」${loc ? '（' + loc + '）' : ''}が現在も残っているか教えてください。`
          )
        },
        {
          label: auditLabel('🧪 Check false positive likelihood', '🧪 誤検知の可能性を確認'),
          prompt: auditLabel(
            `Evaluate whether "${targetLabel}" could be a false positive and what I should verify.`,
            `「${targetLabel}」が誤検知である可能性と、確認すべきポイントを教えてください。`
          )
        }
      ]
    };
  }

  const topIssues = issues.slice(0, 3);
  const topList = topIssues.map(i => `• [${String(i.severity || 'info').toUpperCase()}] ${i.title || ''}`).join('\n');
  const greeting = issues.length > 0
    ? auditLabel(
        `Loaded "${repo.repo}" (${issues.length} saved findings):\n${topList}\n\nWhat would you like to ask or check?`,
        `「${repo.repo}」を読み込みました（保存済みの指摘 ${issues.length}件）：\n${topList}\n\nこのリポジトリについて何を確認・相談しますか？`
      )
    : auditLabel(
        `Loaded "${repo.repo}". What would you like to ask or check?`,
        `「${repo.repo}」を読み込みました。このリポジトリについて何を確認・相談しますか？`
      );
  const greetingHtml = issues.length > 0
    ? `
      <div>${repoBtn} ${auditLabel(`(${issues.length} saved findings):`, `を読み込みました（保存済みの指摘 ${issues.length}件）：`)}</div>
      <div style="display: flex; flex-direction: column; align-items: flex-start; gap: 4px; margin: 8px 0;">
        ${topIssues.map(i => {
          const t = String(i.title || '');
          const s = String(i.severity || 'info').toUpperCase();
          return `<button type="button" class="table-view-btn" style="text-align: left; white-space: normal; padding: 4px 8px;" data-jump-repo="${escapeHtml(repoId)}" data-jump-finding="${escapeHtml(t)}">• [${escapeHtml(s)}] ${escapeHtml(t)}</button>`;
        }).join('')}
      </div>
      <div>${auditLabel('What would you like to ask or check?', 'このリポジトリについて何を確認・相談しますか？')}</div>
    `
    : `
      <div>${repoBtn} ${auditLabel('— What would you like to ask or check?', 'を読み込みました。このリポジトリについて何を確認・相談しますか？')}</div>
    `;

  const suggestions = [
    ...(issues.length > 0 ? [{
      label: auditLabel(`🔍 Prioritize ${issues.length} saved findings`, `🔍 指摘（${issues.length}件）の修正方針を相談`),
      prompt: auditLabel(
        `Summarize the ${issues.length} saved findings in ${repo.repo} (${issues.slice(0, 3).map(i => i.title).join('; ')}) and suggest a prioritized fix plan.`,
        `${repo.repo} の保存済み指摘 ${issues.length}件（${issues.slice(0, 3).map(i => i.title).join('、')} など）について、優先度と修正方針を提案してください。`
      )
    }] : []),
    {
      label: auditLabel('🔄 What changed since the audit?', '🔄 監査時点から何が変わった？'),
      prompt: auditLabel(
        `What changed in ${repo.repo} since the audited commit?`,
        `${repo.repo} について、監査時点のコミットから何が変わったか教えてください。`
      )
    },
    {
      label: auditLabel('🏗️ Summarize architecture & risks', '🏗️ 構成と主なリスクを要約'),
      prompt: auditLabel(
        `Summarize the architecture and key security/quality risks of ${repo.repo}.`,
        `${repo.repo} の構成と主なセキュリティ・品質リスクを要約してください。`
      )
    }
  ];
  return {greeting, greetingHtml, suggestions};
}

function openAuditChat(context = null, preferredProvider = '', forceNew = false) {
  const id = String(selectedDiagram?.id || '');
  const repoName = selectedDiagram?.is_root ? '' : (selectedDiagram?.repo || '');
  const hasContext = Boolean(context && (context.title || context.path));

  if (!forceNew && !hasContext && !preferredProvider && auditConversation && auditConversation.repository === id) {
    renderAuditChat();
    loadAuditLLMConfig(true).then(() => {
      if (auditChatVisible()) renderAuditChat();
    });
    return;
  }

  // If reopening the same repo without a specific finding and a conversation with messages already exists, resume it unless forceNew.
  if (!forceNew && !hasContext) {
    const existing = auditConversations.find(c => c.repository === id && !c.context);
    if (existing) {
      auditConversation = {
        ...existing,
        pending: false,
        selectedProvider: preferredProvider || existing.selectedProvider || ''
      };
      renderAuditChat();
      loadAuditLLMConfig(true).then(() => {
        if (auditChatVisible()) renderAuditChat();
      });
      return;
    }
  }

  const starter = buildAuditStarter(selectedDiagram, context);
  auditConversation = {
    id: 'conv_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7),
    title: buildConversationTitle(selectedDiagram, context),
    repoName,
    repository: id,
    context,
    messages: [],
    greeting: starter.greeting,
    greetingHtml: starter.greetingHtml,
    suggestions: starter.suggestions,
    pending: false,
    draft: '',
    path: context?.path || '',
    line: context?.line ? String(context.line) : '',
    selectedProvider: preferredProvider || '',
    updatedAt: new Date().toISOString()
  };
  saveAuditConversations();
  renderAuditChat();
  loadAuditLLMConfig(true).then(() => {
    if (auditChatVisible()) renderAuditChat();
  });
}

function selectAuditConversationById(convId) {
  const target = auditConversations.find(c => c.id === convId);
  if (!target) return;
  auditConversation = {...target, pending: false};
  if (typeof diagrams !== 'undefined' && Array.isArray(diagrams)) {
    const idx = diagrams.findIndex(d => String(d.id) === String(target.repository));
    if (idx >= 0 && typeof selectDiagram === 'function' && String(selectedDiagram?.id || '') !== String(target.repository)) {
      selectDiagram(idx);
    }
  }
  renderAuditChat();
}

function extractCleanFindingDesc(panel, issueEl) {
  const rawDataDesc = panel?.dataset?.findingDesc || '';
  if (rawDataDesc.trim()) return rawDataDesc.trim();
  const descEl = issueEl?.querySelector('.saved-finding-description');
  if (!descEl) return '';
  const clone = descEl.cloneNode(true);
  clone.querySelectorAll('.issue-actions, button').forEach(el => el.remove());
  return (clone.textContent || '').trim();
}

function chatAboutFinding(button, preferredProvider = '') {
  const panel = button.closest('.finding-source') || button.closest('.audit-issue')?.querySelector('.finding-source');
  const issueEl = button.closest('.audit-issue');
  const baseContext = panel ? JSON.parse(panel.dataset.context) : {};
  const context = {
    ...baseContext,
    title: panel?.dataset.findingTitle || issueEl?.querySelector('.issue-title')?.textContent?.trim() || '',
    severity: panel?.dataset.findingSeverity || issueEl?.querySelector('.issue-severity')?.textContent?.trim() || '',
    desc: extractCleanFindingDesc(panel, issueEl)
  };
  openAuditChat(context, preferredProvider, true);
  publishNativeWorkspace('chat');
}

function closeFindingContextMenu() {
  document.getElementById('finding-context-menu')?.remove();
}

async function rescanSingleFinding(issueEl) {
  if (!issueEl) return;
  issueEl.open = true;
  const loadBtn = issueEl.querySelector('[data-load-finding-source]');
  if (loadBtn) {
    await loadFindingSource(loadBtn);
    return;
  }
  const repoId = String(selectedDiagram?.id || '');
  if (!repoId) return;
  const bodyEl = issueEl.querySelector('.issue-body') || issueEl;
  let resultEl = issueEl.querySelector('[data-evidence-result]');
  if (!resultEl) {
    resultEl = document.createElement('div');
    resultEl.setAttribute('data-evidence-result', '');
    resultEl.setAttribute('aria-live', 'polite');
    bodyEl.prepend(resultEl);
  }
  const rawPathText = (issueEl.querySelector('.issue-path')?.textContent || '').trim();
  const pathMatch = rawPathText.match(/^([^\s:]+)(?::(\d+))?/);
  const rawPath = pathMatch ? pathMatch[1] : '';
  const hasExplicitLine = Boolean(pathMatch && pathMatch[2]);
  const rawLine = hasExplicitLine ? Number(pathMatch[2]) : null;
  const titleText = (issueEl.querySelector('.issue-title')?.textContent || '').trim();
  const osvPkgMatch = titleText.match(/\[OSV[^\]]*\]\s+([^\s(]+)/);
  const searchTerm = !hasExplicitLine && osvPkgMatch ? osvPkgMatch[1] : '';
  const looksLikeFile = Boolean(rawPath && !rawPath.includes('未記録') && rawPath !== 'Location' && (rawPath.includes('.') || rawPath.includes('/')));
  resultEl.innerHTML = `<p class="audit-chat-pending" role="status"><span class="audit-spinner" aria-hidden="true"></span><span>${auditLabel('Checking latest GitHub status for this finding…', 'この指摘の最新状態を GitHub で確認中…')}</span></p>`;
  setIssueRescanSpinning(issueEl, true);
  try {
    let info;
    if (looksLikeFile) {
      try {
        const reqPayload = rawLine
          ? {repository: repoId, path: rawPath, line: rawLine}
          : (searchTerm ? {repository: repoId, path: rawPath, search: searchTerm} : {repository: repoId, path: rawPath, line: 1});
        info = await auditRequest('evidence', reqPayload);
      } catch (_) {
        info = await auditRequest('evidence', {repository: repoId});
      }
    } else {
      info = await auditRequest('evidence', {repository: repoId});
    }
    resultEl.innerHTML = info.path ? sourceComparison(info) : `<div class="audit-comparison">${repositoryFacts(info)}</div>`;
  } catch (error) {
    renderEvidenceErrorBanner(resultEl, error.message, () => rescanSingleFinding(issueEl));
  } finally {
    setIssueRescanSpinning(issueEl, false);
  }
}

function showFindingContextMenu(event, issueEl) {
  event.preventDefault();
  closeFindingContextMenu();

  const panel = issueEl.querySelector('.finding-source');
  const baseContext = panel ? JSON.parse(panel.dataset.context) : {};
  const titleText = panel?.dataset.findingTitle || issueEl.querySelector('.issue-title')?.textContent?.trim() || '';
  const severityText = panel?.dataset.findingSeverity || issueEl.querySelector('.issue-severity')?.textContent?.trim() || '';
  const metaText = issueEl.querySelector('.issue-path, .issue-file')?.textContent?.trim() || '';
  const descText = extractCleanFindingDesc(panel, issueEl);
  const context = {...baseContext, title: titleText, severity: severityText, desc: descText};

  const menu = document.createElement('div');
  menu.id = 'finding-context-menu';
  menu.setAttribute('role', 'menu');
  Object.assign(menu.style, {
    position: 'fixed',
    left: `${Math.min(event.clientX, window.innerWidth - 240)}px`,
    top: `${Math.min(event.clientY, window.innerHeight - 140)}px`,
    zIndex: '10000',
    minWidth: '210px',
    padding: '6px',
    borderRadius: '10px',
    background: 'rgba(30, 32, 40, 0.96)',
    border: '1px solid rgba(255, 255, 255, 0.14)',
    boxShadow: '0 12px 32px rgba(0, 0, 0, 0.45)',
    backdropFilter: 'blur(12px)',
    display: 'flex',
    flexDirection: 'column',
    gap: '2px'
  });

  const makeItem = (label, onClick) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.setAttribute('role', 'menuitem');
    btn.textContent = label;
    Object.assign(btn.style, {
      textAlign: 'left',
      padding: '7px 10px',
      borderRadius: '6px',
      border: 'none',
      background: 'transparent',
      color: '#f8fafc',
      fontSize: '0.84rem',
      cursor: 'pointer'
    });
    btn.onmouseenter = () => { btn.style.background = 'rgba(56, 189, 248, 0.22)'; };
    btn.onmouseleave = () => { btn.style.background = 'transparent'; };
    btn.onclick = () => {
      closeFindingContextMenu();
      onClick();
    };
    return btn;
  };

  menu.append(
    makeItem(auditLabel('🔄 Re-scan this finding', '🔄 この指摘だけを再スキャン'), () => {
      rescanSingleFinding(issueEl);
    }),
    makeItem(auditLabel('💬 Ask AI / Copilot about this finding', '💬 AI / Copilot にこの指摘を相談'), () => {
      openAuditChat(context, '', true);
      publishNativeWorkspace('chat');
    }),
    makeItem(auditLabel('📋 Copy finding details', '📋 指摘内容をコピー'), () => {
      const text = [titleText, metaText, descText].filter(Boolean).join('\n');
      navigator.clipboard?.writeText(text).catch(() => {});
    })
  );

  document.body.append(menu);
}

if (!window.__repoaudtFindingMenuBound) {
  window.__repoaudtFindingMenuBound = true;
  document.addEventListener('contextmenu', event => {
    const issueEl = event.target?.closest?.('.audit-issue');
    if (issueEl) {
      showFindingContextMenu(event, issueEl);
    } else {
      closeFindingContextMenu();
    }
  });
  document.addEventListener('click', closeFindingContextMenu);
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') closeFindingContextMenu();
  });
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
  const cfg = auditLLMConfig;
  const configured = getConfiguredAuditProviders(cfg);
  const activeProv = cfg?.active_provider && configured.includes(cfg.active_provider)
    ? cfg.active_provider
    : (configured[0] || '');
  if (!state.selectedProvider || !configured.includes(state.selectedProvider)) {
    state.selectedProvider = activeProv;
  }
  const formatProvider = prov => {
    const label = AUDIT_PROVIDER_LABELS[prov] || prov;
    const model = cfg?.models?.[prov] || '';
    return model ? `${label} (${model})` : label;
  };
  const aiStatusHtml = !cfg
    ? `<p class="audit-note">${auditLabel('Checking configured AI providers…', '接続済みAIを確認中…')}</p>`
    : configured.length === 0
      ? `<div class="audit-chat-error" role="status" style="padding: 8px 12px; border-radius: 8px; border: 1px solid currentColor; margin-top: 8px;">
          ${auditLabel(
            'No AI provider is connected yet. Open "Connections > AI connections" in the left sidebar to configure OpenAI, Claude, Gemini, Groq, GitHub Copilot, or a Local LLM.',
            'AI がまだ1つも接続されていません。左サイドバーの「接続 ＞ AI 接続」から OpenAI / Claude / Gemini / Groq / GitHub Copilot / ローカル LLM のいずれかを接続してください。'
          )}
        </div>`
      : configured.length === 1
        ? `<p class="audit-note" style="margin-top: 6px;">🤖 ${auditLabel('Active AI', '使用中のAI')}: <strong>${escapeHtml(formatProvider(configured[0]))}</strong></p>`
        : `<div class="issue-actions" style="margin-top: 8px; align-items: center;">
            <label style="display: flex; align-items: center; gap: 8px; font-size: 0.85rem;">
              <span>🤖 ${auditLabel('AI model', '使用AI')}</span>
              <select id="audit-chat-provider">
                ${configured.map(prov => `<option value="${escapeHtml(prov)}" ${prov === state.selectedProvider ? 'selected' : ''}>${escapeHtml(formatProvider(prov))}</option>`).join('')}
              </select>
            </label>
          </div>`;

  const displayRepo = state.repoName || (selectedDiagram?.is_root ? '' : (selectedDiagram?.repo || ''));
  const displayTitle = state.title || buildConversationTitle(selectedDiagram, context);
  const historyOptionsHtml = auditConversations.length > 0
    ? `<div class="issue-actions" style="margin-top: 6px; align-items: center; flex-wrap: wrap;">
        <label style="display: flex; align-items: center; gap: 8px; font-size: 0.85rem;">
          <span>💬 ${auditLabel('Chat history', 'チャット履歴')}</span>
          <select id="audit-chat-history" style="max-width: 440px;">
            ${auditConversations.map(c => {
              const labelRepo = c.repoName ? `[${c.repoName}] ` : '';
              const msgCount = Array.isArray(c.messages) ? c.messages.length : 0;
              const suffix = msgCount > 0 ? ` (${msgCount})` : '';
              return `<option value="${escapeHtml(c.id)}" ${c.id === state.id ? 'selected' : ''}>${escapeHtml(labelRepo + (c.title || 'Chat') + suffix)}</option>`;
            }).join('')}
          </select>
        </label>
        <button type="button" id="audit-chat-new" class="table-view-btn">${auditLabel('+ New chat', '＋ 新しいチャット')}</button>
      </div>`
    : '';

  section.innerHTML = `<div class="audit-chat-inner">
    <header>
      <div class="issue-actions" style="margin-bottom: 8px;">
        <button type="button" id="audit-chat-back" class="table-view-btn">${auditLabel('← Back to Audit Results', '← 監査結果に戻る')}</button>
      </div>
      <h2>${escapeHtml(displayTitle)}</h2>
      <p style="font-size: 0.88rem; margin-top: 2px;">
        ${auditLabel('Audit chat', '監査チャット')}${displayRepo ? ` · <strong>${escapeHtml(displayRepo)}</strong>` : ''}
      </p>
      ${historyOptionsHtml}
      ${aiStatusHtml}
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
      ${(state.greetingHtml || state.greeting) ? `<article>
        <strong>${escapeHtml(state.selectedProvider === 'copilot' ? 'GitHub Copilot' : 'AI')}</strong>
        ${state.greetingHtml ? `<div style="margin-top: 6px;">${state.greetingHtml}</div>` : `<p style="white-space: pre-line;">${escapeHtml(state.greeting)}</p>`}
      </article>` : ''}
      ${state.latest ? `<details><summary>${auditLabel('Latest GitHub evidence', '最新のGitHub確認結果')}</summary>
        ${state.latest.path ? sourceComparison(state.latest) : repositoryFacts(state.latest)}</details>` : ''}
      ${state.messages.map(message => `<article>
        <strong>${message.role === 'user'
          ? auditLabel('You', 'あなた')
          : escapeHtml(message.provider ? `AI (${AUDIT_PROVIDER_LABELS[message.provider] || message.provider}${message.model ? ' · ' + message.model : ''})` : 'AI')}</strong>
        <p>${escapeHtml(message.text)}</p>
      </article>`).join('')}
      ${state.pending ? `<p class="audit-chat-pending" role="status"><span class="audit-spinner" aria-hidden="true"></span><span>${auditLabel('Checking GitHub and waiting for AI…', 'GitHub を確認し、AI の回答を待っています…')}</span></p>` : ''}
      ${state.error ? `<p class="audit-chat-error" role="alert">${escapeHtml(state.error)}</p>` : ''}
    </div>
    ${state.suggestions && state.suggestions.length && !state.pending ? `<div class="issue-actions" style="margin-bottom: 8px; flex-wrap: wrap;">
      ${state.suggestions.map((item, idx) => `<button type="button" class="table-view-btn" data-audit-suggestion="${idx}">${escapeHtml(item.label)}</button>`).join('')}
    </div>` : ''}
    <form>
      <label for="audit-question">${auditLabel('Question', '質問')}</label>
      <textarea id="audit-question" required maxlength="4000" rows="3" placeholder="${auditLabel('What changed since the audit?', '監査時点から何が変わった？')}">${escapeHtml(state.draft)}</textarea>
      <div class="issue-actions">
        <button class="table-view-btn workspace-primary" type="submit" ${state.pending ? 'disabled' : ''}>
          ${state.pending
            ? `<span class="audit-spinner" aria-hidden="true"></span> ${auditLabel('Waiting for AI…', 'AI 応答待ち…')}`
            : auditLabel('Check GitHub and ask AI', 'GitHubを確認してAIに聞く')}
        </button>
      </div>
      <p class="audit-note">${auditLabel('Your question, recent conversation and evidence metadata are sent to the configured AI provider.', '質問・直近の会話・監査の比較結果を設定済みAIに送ります。')}</p>
    </form>`}
  </div>`;
  const backBtn = section.querySelector('#audit-chat-back');
  if (backBtn) {
    backBtn.onclick = () => jumpToAuditRepoPage(state.repository, state.context?.title || '');
  }
  const historySelect = section.querySelector('#audit-chat-history');
  if (historySelect) {
    historySelect.onchange = () => selectAuditConversationById(historySelect.value);
  }
  const newChatBtn = section.querySelector('#audit-chat-new');
  if (newChatBtn) {
    newChatBtn.onclick = () => openAuditChat(null, state.selectedProvider || '', true);
  }
  const providerSelect = section.querySelector('#audit-chat-provider');
  if (providerSelect) {
    providerSelect.onchange = () => {
      state.selectedProvider = providerSelect.value;
      saveAuditConversations();
    };
  }
  for (const btn of section.querySelectorAll('[data-jump-repo]')) {
    btn.onclick = () => jumpToAuditRepoPage(btn.dataset.jumpRepo, btn.dataset.jumpFinding || '');
  }
  for (const btn of section.querySelectorAll('[data-audit-suggestion]')) {
    btn.onclick = () => {
      const idx = Number(btn.dataset.auditSuggestion);
      const item = state.suggestions?.[idx];
      if (!item) return;
      state.draft = item.prompt;
      sendAuditQuestion(state);
    };
  }
  const input = section.querySelector('textarea');
  if (!input) return;
  input.oninput = () => { state.draft = input.value; };
  input.onkeydown = event => {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing && event.keyCode !== 229) {
      event.preventDefault();
      sendAuditQuestion(state);
    }
  };
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
  saveAuditConversations();
  renderAuditChat();
  try {
    const findingPayload = state.context && (state.context.title || state.context.desc)
      ? {
          finding: {
            title: state.context.title || '',
            severity: state.context.severity || '',
            path: state.context.path || '',
            line: state.context.line || '',
            desc: state.context.desc || ''
          }
        }
      : {};
    const response = await auditRequest('chat', {
      repository: state.repository, ...location, ...findingPayload, question, history, language: currentLang,
      ...(state.selectedProvider ? {provider: state.selectedProvider} : {})
    });
    state.latest = response;
    if (response.answer) {
      state.messages.push({
        role: 'assistant',
        text: response.answer,
        provider: response.provider,
        model: response.model
      });
    } else state.error = response.ai_error;
  } catch (error) {
    state.error = error.message;
    if (!state.draft) state.draft = question;
    state.messages.pop();
  } finally {
    state.pending = false;
    saveAuditConversations();
    if (auditConversation === state && auditChatVisible()) renderAuditChat();
  }
}
