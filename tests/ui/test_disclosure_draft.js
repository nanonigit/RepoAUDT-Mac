const {strict: assert} = require('node:assert');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const {test} = require('node:test');
const {runInNewContext} = require('node:vm');

const source = readFileSync(resolve(__dirname, '../../Resources/webui/audit-evidence.js'), 'utf8');
const commit = 'a'.repeat(40);
const repo = {
  commit_hash: commit,
  source_revision: {kind: 'github_commit', commit_sha: commit, repository: 'sample/repo'}
};
const issue = {
  id: 'CWE-862-python-local-privileged-route',
  scanner: 'authorization-evidence',
  file: 'backend/server.py:123',
  desc: 'arbitrary fixture text',
  diff: 'fixture patch',
  evidence_chain: [{source: 'fixture source'}]
};

function context(lang = 'en', navigator = {}) {
  const sandbox = {currentLang: lang, navigator};
  runInNewContext(source, sandbox);
  return sandbox;
}

test('draft contains pinned evidence and no saved raw text in either language', () => {
  for (const lang of ['en', 'ja']) {
    const {text, policy} = context(lang).disclosureDraft(repo, issue);
    assert.match(text, /CWE-862/);
    assert.match(text, new RegExp('/blob/' + commit + '/backend/server.py#L123'));
    assert.doesNotMatch(text, /arbitrary fixture text|fixture patch|fixture source/);
    assert.match(text, lang === 'en' ? /verification scope/ : /確認範囲/);
    assert.equal(policy, 'https://github.com/sample/repo/security/policy');
  }
});

test('unsupported or unpinned findings cannot initialize a disclosure draft', () => {
  const {disclosureDraft} = context();
  assert.equal(disclosureDraft(repo, {...issue, file: '../server.py:1'}), null);
  assert.equal(disclosureDraft(repo, {...issue, scanner: 'gitleaks'}), null);
  assert.equal(disclosureDraft({...repo, commit_hash: 'b'.repeat(40)}, issue), null);
});

test('copy writes the edited text to the clipboard', async () => {
  let copied = '';
  const {copyDisclosureDraft} = context('en', {clipboard: {writeText: async value => { copied = value; }}});
  const status = {textContent: ''};
  const textarea = {value: 'Edited draft'};
  const editor = {querySelector: selector => selector === 'textarea' ? textarea : status};
  await copyDisclosureDraft({closest: () => editor});
  assert.equal(copied, 'Edited draft');
  assert.equal(status.textContent, 'Copied');
});
