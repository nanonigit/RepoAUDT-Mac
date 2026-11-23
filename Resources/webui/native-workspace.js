/* Display-only bridge for the SwiftUI sibling-app workspace. */
function publishNativeWorkspace(page = null) {
  const bridge = window.webkit?.messageHandlers?.workspace;
  if (!bridge) return;
  bridge.postMessage({
    page,
    repositories: diagrams.filter(item => !item.is_root).map(item => ({
      id: String(item.id),
      name: String(item.repo || ''),
      url: String(item.github_url || ''),
      commit: String(item.commit_hash || ''),
      description: String(item.description || ''),
      findings: getWorkspaceIssues(item).length,
      severity: getWorkspaceIssues(item).reduce((highest, issue) => {
        const ranks = {critical: 5, high: 4, medium: 3, warning: 3, low: 2, info: 1};
        const next = String(issue.severity || '').toLowerCase();
        return (ranks[next] || 0) > (ranks[highest] || 0) ? next : highest;
      }, ''),
      updatedAt: String(item.github_meta?.pushedAt || item.github_meta?.updatedAt || item.updatedAt || item.analyzed_at || ''),
      analyzedAt: String(item.analyzed_at || '')
    })),
    selectedID: selectedDiagram ? String(selectedDiagram.id) : null
  });
}

async function nativeWorkspaceCommand(command, value) {
  switch (command) {
    case 'language':
      setLanguage(value === 'en' ? 'en' : 'ja');
      if (currentViewMode === 'coderabbit') renderCodeRabbitView();
      if (auditChatVisible()) renderAuditChat();
      break;
    case 'repository': {
      closeAuditChat();
      const index = diagrams.findIndex(item => String(item.id) === value);
      if (index >= 0) await selectDiagram(index);
      break;
    }
    case 'copilot-chat': {
      const index = diagrams.findIndex(item => String(item.id) === value);
      if (index >= 0) await selectDiagram(index);
      openAuditChat(null, 'copilot');
      break;
    }
    case 'page':
      if (selectedDiagram?.is_root) {
        const first = diagrams.findIndex(item => !item.is_root);
        if (first >= 0) await selectDiagram(first);
      }
      if (value === 'chat') { openAuditChat(); break; }
      closeAuditChat();
      if (['arch', 'seq', 'coderabbit'].includes(value)) switchViewMode(value);
      break;
    case 'analyze': openAnalyzeModal(); break;
    case 'settings': openAdminSettingsModal(); break;
    case 'details': toggleInspectorPane(); break;
    case 'refresh': {
      const id = selectedDiagram?.id;
      const mode = currentViewMode;
      await syncSavedAnalysesFromServer();
      const index = diagrams.findIndex(item => item.id === id);
      if (index >= 0) await selectDiagram(index);
      switchViewMode(mode);
      break;
    }
  }
  publishNativeWorkspace();
}

window.addEventListener('DOMContentLoaded', () => {
  if (!window.webkit?.messageHandlers?.workspace) return;
  document.documentElement.classList.add('native-host');
  // Start with a full-width work area. Details open on explicit component selection.
  document.body.classList.add('inspector-collapsed');
  publishNativeWorkspace();
});

function renderNativeInspector() {
  const en = currentLang === 'en';
  const {name, path, spec = {}, repoItem} = selectedNodeData;
  const related = getRepoActionItems(repoItem).filter(issue =>
    name === repoItem.repo || issue.target_node === name ||
    (path && String(issue.file || '').includes(path)));
  inspEmpty.style.display = 'none';
  inspContent.style.display = 'block';
  inspContent.innerHTML = `
    <section class="workspace-inspector">
      <h2>${escapeHtml(name)}</h2>
      <code>${escapeHtml(path || '')}</code>
      <h3>${en ? 'Role' : '役割'}</h3>
      <p>${escapeHtml(spec.desc || repoItem.description || (en ? 'No description recorded.' : '説明は記録されていません。'))}</p>
      <h3>${en ? 'Saved findings' : '保存済みの指摘'} · ${related.length}</h3>
      ${related.length ? `<ul>${related.map(issue => `<li>${escapeHtml(issue.title || '')}</li>`).join('')}</ul>` :
        `<p>${en ? 'No related findings recorded.' : '関連する指摘は記録されていません。'}</p>`}
      <button type="button" class="table-view-btn" onclick="switchViewMode('coderabbit'); setInspectorCollapsed(true)">${en ? 'Open audit results' : '監査結果で確認'}</button>
      <h3>${en ? 'Repository' : 'リポジトリ'}</h3>
      <p>${escapeHtml(repoItem.repo)}</p>
      <code>${escapeHtml(repoItem.commit_hash || (en ? 'Commit not recorded' : 'コミット未記録'))}</code>
    </section>`;
}
