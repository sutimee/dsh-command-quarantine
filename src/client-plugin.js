// ============================================================================
// 归档：动态插件时代的历史版本，仅供开发/临时参考；生产请使用 lib/ 固化版。
// ============================================================================
/**
 * DSH Command Quarantine — client half
 * =====================================================================
 * Two UI surfaces, both in the shipped DSH visual language (--dsw-alias-*):
 *
 * 1. Settings → Plugins → Command Quarantine: a collapsible PluginCard-style
 *    entry with layered review scope (global / per-session / off), the
 *    intercepted-tool checklist discovered from the live tool registry, the
 *    LLM reviewer options, the delegation guard, and the pending-approval
 *    panel.
 * 2. Composer row (conversation.input.left): a small per-session switch
 *    styled like the access-mode control. Greyed out while global review is
 *    on; otherwise toggles whether THIS session (and its subagent lineage)
 *    is intercepted.
 *
 * All state lives on the Host side in <workspace>\quarantine\config.json;
 * this UI is a thin RPC surface over the Package-private handlers.
 */

const CSS = `
.cq-card {
  list-style: none;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 12px;
  background: var(--dsw-alias-bg-layer-3);
  transition: border-color .16s, background .16s;
}
.cq-card:hover { border-color: var(--dsw-alias-label-dimmed); }
.cq-cardOpen { background: var(--dsw-alias-bg-layer-2); border-color: var(--dsw-alias-label-dimmed); }

.cq-header {
  width: 100%;
  appearance: none;
  border: 0;
  background: none;
  font: inherit;
  color: inherit;
  text-align: left;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 16px;
  border-radius: 12px;
}
.cq-header:focus-visible { outline: 2px solid var(--dsw-alias-brand-primary); outline-offset: -2px; }

.cq-headText { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 4px; }
.cq-name { font-size: 15px; font-weight: 600; line-height: 1.4; color: var(--dsw-alias-label-primary); }
.cq-description { font-size: 13px; line-height: 1.5; color: var(--dsw-alias-label-tertiary); }

.cq-chevron { flex: none; color: var(--dsw-alias-label-tertiary); transition: transform .16s; font-size: 12px; }
.cq-chevronOpen { transform: rotate(180deg); }

.cq-pending {
  flex: none;
  border-radius: 999px;
  padding: 1px 8px;
  font-size: 11px;
  line-height: 17px;
  font-weight: 500;
  white-space: nowrap;
  background: var(--dsw-alias-bg-module-platform);
  color: var(--dsw-alias-label-secondary);
}

.cq-body { border-top: 1px solid var(--dsw-alias-border-l2); margin: 0 16px; padding: 4px 0 12px; display: flex; flex-direction: column; gap: 14px; font-size: 13px; line-height: 1.5; }
.cq-section { padding-top: 12px; display: flex; flex-direction: column; gap: 8px; }
.cq-section + .cq-section { border-top: 1px solid var(--dsw-alias-border-l2); }
.cq-section-title { font-size: 12px; font-weight: 600; line-height: 1.5; color: var(--dsw-alias-label-tertiary); }

.cq-row { display: flex; align-items: center; gap: 8px; color: var(--dsw-alias-label-primary); }
.cq-row input[type="checkbox"], .cq-row input[type="radio"] { margin: 0; accent-color: var(--dsw-alias-brand-primary); }
.cq-hint { font-size: 12px; line-height: 1.5; color: var(--dsw-alias-label-tertiary); }
.cq-warn { font-size: 12px; line-height: 1.5; color: var(--dsw-alias-label-error); }

.cq-tools { display: flex; flex-direction: column; gap: 2px; max-height: 160px; overflow: auto; }

.cq-select {
  appearance: none;
  padding: 5px 10px;
  border-radius: 8px;
  border: 1px solid var(--dsw-alias-border-l2);
  background: var(--dsw-alias-bg-layer-2);
  color: var(--dsw-alias-label-primary);
  font: inherit;
  font-size: 13px;
  max-width: 100%;
}
.cq-select:disabled { opacity: 0.4; cursor: default; }

.cq-pending-item { border: 1px solid var(--dsw-alias-border-l2); border-radius: 10px; padding: 10px; display: flex; flex-direction: column; gap: 6px; background: var(--dsw-alias-bg-layer-3); }
.cq-pending-meta { display: flex; gap: 8px; flex-wrap: wrap; font-size: 12px; color: var(--dsw-alias-label-tertiary); }
.cq-pending-reason { font-size: 12px; line-height: 1.5; color: var(--dsw-alias-label-secondary); white-space: pre-wrap; max-height: 72px; overflow: auto; }

.cq-actions { display: flex; align-items: center; gap: 8px; }
.cq-actionsSpacer { flex: 1; }

.cq-btn {
  appearance: none;
  border: 1px solid transparent;
  border-radius: 8px;
  padding: 5px 14px;
  font: inherit;
  font-size: 13px;
  line-height: 1.5;
  cursor: pointer;
}
.cq-btn.ghost { border-color: var(--dsw-alias-border-l2); background: none; color: var(--dsw-alias-label-secondary); }
.cq-btn.ghost:hover:not(:disabled) { color: var(--dsw-alias-label-primary); border-color: var(--dsw-alias-label-dimmed); }
.cq-btn.primary { background: var(--dsw-alias-brand-primary); color: #fff; }
.cq-btn.danger { border-color: var(--dsw-alias-label-error); background: none; color: var(--dsw-alias-label-error); }
.cq-btn.danger:hover:not(:disabled) { background: var(--dsw-alias-label-error); color: #fff; }
.cq-btn:disabled { opacity: 0.4; cursor: default; }
.cq-btn:focus-visible { outline: 2px solid var(--dsw-alias-brand-primary); outline-offset: 1px; }

.cq-msg { font-size: 12px; line-height: 1.5; color: var(--dsw-alias-label-secondary); white-space: pre-wrap; word-break: break-word; }

/* composer-row session switch (styled like the access-mode control) */
.cq-session-wrap { position: relative; display: inline-flex; }
.cq-session-btn {
  appearance: none;
  border: 1px solid var(--dsw-alias-border-l2);
  background: var(--dsw-alias-bg-layer-2);
  color: var(--dsw-alias-label-secondary);
  border-radius: 999px;
  padding: 3px 10px;
  font: inherit;
  font-size: 12px;
  line-height: 18px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
}
.cq-session-btn:hover:not(:disabled) { color: var(--dsw-alias-label-primary); border-color: var(--dsw-alias-label-dimmed); }
.cq-session-btn.on { color: var(--dsw-alias-brand-primary); border-color: var(--dsw-alias-brand-primary); }
.cq-session-btn:disabled { opacity: 0.5; cursor: default; }
.cq-session-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }

.cq-session-menu {
  position: absolute;
  top: calc(100% + 6px);
  left: 0;
  z-index: 40;
  min-width: 260px;
  border: 1px solid var(--dsw-alias-border-l2);
  border-radius: 10px;
  background: var(--dsw-alias-bg-layer-2);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.16);
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  font-size: 13px;
  line-height: 1.5;
  color: var(--dsw-alias-label-primary);
}
.cq-session-menu-title { font-size: 12px; font-weight: 600; color: var(--dsw-alias-label-tertiary); }
.cq-session-menu-row { display: flex; align-items: center; gap: 8px; }
`

function SettingsCard() {
  const [cfg, setCfg] = React.useState(null)
  const [models, setModels] = React.useState([])
  const [pending, setPending] = React.useState([])
  const [busy, setBusy] = React.useState(false)
  const [msg, setMsg] = React.useState('')
  const [open, setOpen] = React.useState(false)

  function refreshPending() {
    host.call('pending.list').then((r) => {
      if (r && Array.isArray(r.pending)) setPending(r.pending)
      else if (r && r.error) setMsg('待审批刷新失败：' + r.error)
    }).catch((e) => setMsg('待审批刷新失败：' + String(e && e.message ? e.message : e)))
  }

  function loadModels(provider) {
    if (!provider) {
      setModels([])
      return
    }
    host.call('models.list', { provider }).then((r) => {
      setModels((r && Array.isArray(r.models)) ? r.models : [])
    }).catch(() => setModels([]))
  }

  React.useEffect(() => {
    let alive = true
    host.call('config.get').then((c) => {
      if (!alive || !c || c.error) return
      setCfg(c)
      if (c.reviewerMode === 'custom' && c.reviewerProvider) loadModels(c.reviewerProvider)
    }).catch(() => {})
    refreshPending()
    return () => { alive = false }
  }, [])

  function save(patch) {
    setBusy(true)
    host.call('config.set', patch).then((c) => {
      setBusy(false)
      if (c && c.ok) {
        setCfg((prev) => Object.assign({}, prev, c))
        setMsg('已保存')
      } else {
        setMsg('保存失败：' + (c && c.error ? c.error : 'unknown error'))
      }
    }).catch((e) => {
      setBusy(false)
      setMsg('保存失败：' + String(e && e.message ? e.message : e))
    })
  }

  function toggleTool(name) {
    if (cfg === null) return
    const candidates = Array.isArray(cfg.toolCandidates) ? cfg.toolCandidates : []
    const current = Array.isArray(cfg.toolDenyList) ? cfg.toolDenyList : []
    const enabled = current.length === 0 ? candidates.slice() : current.slice()
    const idx = enabled.indexOf(name)
    let next
    if (idx === -1) next = enabled.concat([name])
    else {
      next = enabled.filter(n => n !== name)
      if (next.length === candidates.length) next = [] /* all selected → auto default */
    }
    save({ toolDenyList: next })
  }

  function approve(id) {
    setBusy(true)
    setMsg('正在批准并执行 ' + id + ' …')
    host.call('pending.approve', { command_id: id }).then((r) => {
      setBusy(false)
      if (r && r.ok) {
        setMsg('已批准并执行（exit ' + r.exit_code + '）\n' + (r.stdout_tail || ''))
      } else {
        setMsg('批准失败：' + (r && r.error ? r.error : 'unknown error'))
      }
      refreshPending()
    }).catch((e) => {
      setBusy(false)
      setMsg('批准失败：' + String(e && e.message ? e.message : e))
    })
  }

  function reject(id) {
    setBusy(true)
    host.call('pending.reject', { command_id: id }).then((r) => {
      setBusy(false)
      setMsg(r && r.ok ? '已拒绝 ' + id : ('拒绝失败：' + (r && r.error ? r.error : 'unknown error')))
      refreshPending()
    }).catch((e) => {
      setBusy(false)
      setMsg('拒绝失败：' + String(e && e.message ? e.message : e))
    })
  }

  const header = React.createElement('button', {
    type: 'button',
    className: 'cq-header',
    'aria-expanded': open,
    onClick: () => setOpen(!open),
  },
    React.createElement('span', { className: 'cq-headText' },
      React.createElement('span', { className: 'cq-name' }, 'Command Quarantine'),
      React.createElement('span', { className: 'cq-description' }, '命令隔离区：拦截直接命令执行；命令经提交 → 审查 → 按 ID 执行，全程审计。'),
    ),
    pending.length > 0 ? React.createElement('span', { className: 'cq-pending' }, '待审批 ' + pending.length) : null,
    React.createElement('span', { className: 'cq-chevron' + (open ? ' cq-chevronOpen' : '') }, '▾'),
  )

  const providers = (cfg !== null && cfg.providers && Array.isArray(cfg.providers)) ? cfg.providers : []
  const candidates = (cfg !== null && Array.isArray(cfg.toolCandidates)) ? cfg.toolCandidates : []
  const denyList = (cfg !== null && Array.isArray(cfg.toolDenyList)) ? cfg.toolDenyList : []
  const toolChecked = (name) => (denyList.length === 0 ? candidates.indexOf(name) !== -1 : denyList.indexOf(name) !== -1)

  const pendingRows = pending.map((p) => React.createElement('div', { className: 'cq-pending-item', key: p.command_id },
    React.createElement('div', null,
      React.createElement('strong', null, p.intent || '(无意图说明)'),
      React.createElement('span', { className: 'cq-pending-meta' },
        React.createElement('span', null, p.command_id),
        React.createElement('span', null, p.tool),
      ),
    ),
    React.createElement('div', { className: 'cq-pending-reason' }, p.reason || ''),
    React.createElement('div', { className: 'cq-actions' },
      React.createElement('button', { className: 'cq-btn primary', disabled: busy, onClick: () => approve(p.command_id) }, '批准并执行'),
      React.createElement('button', { className: 'cq-btn danger', disabled: busy, onClick: () => reject(p.command_id) }, '拒绝'),
    ),
  ))

  let body = null
  if (cfg !== null) {
    body = React.createElement('div', { className: 'cq-body' },
      React.createElement('div', { className: 'cq-section' },
        React.createElement('div', { className: 'cq-section-title' }, '审查范围 Review scope'),
        React.createElement('label', { className: 'cq-row' },
          React.createElement('input', {
            type: 'radio',
            name: 'cq-review-scope',
            checked: cfg.reviewScope === 'global' || cfg.reviewScope === undefined,
            disabled: busy,
            onChange: () => save({ reviewScope: 'global' }),
          }),
          '全局审查',
        ),
        React.createElement('div', { className: 'cq-hint' }, '所有会话、所有模型与 agent 预设、所有子代理的命令执行都被拦截（输入框底部的会话开关将置灰）。'),
        React.createElement('label', { className: 'cq-row' },
          React.createElement('input', {
            type: 'radio',
            name: 'cq-review-scope',
            checked: cfg.reviewScope === 'per-session',
            disabled: busy,
            onChange: () => save({ reviewScope: 'per-session' }),
          }),
          '按会话审查',
        ),
        React.createElement('div', { className: 'cq-hint' }, '默认不审查；在输入框底部的开关中为单个会话开启，其子代理按血缘一并拦截。'),
        React.createElement('label', { className: 'cq-row' },
          React.createElement('input', {
            type: 'radio',
            name: 'cq-review-scope',
            checked: cfg.reviewScope === 'off',
            disabled: busy,
            onChange: () => save({ reviewScope: 'off' }),
          }),
          '关闭审查',
        ),
        React.createElement('div', { className: 'cq-warn' }, '所有会话（含子代理）都不再拦截任何命令执行——请确认这是你有意的选择。'),
      ),
      React.createElement('div', { className: 'cq-section' },
        React.createElement('div', { className: 'cq-section-title' }, '受拦截工具 Intercepted tools'),
        React.createElement('label', { className: 'cq-row' },
          React.createElement('input', {
            type: 'checkbox',
            checked: !!cfg.interceptTools,
            disabled: busy,
            onChange: () => save({ interceptTools: !cfg.interceptTools }),
          }),
          '拦截命令执行工具',
        ),
        React.createElement('div', { className: 'cq-hint' }, '插件加载时自动发现的可拦截工具（当前部署：' + candidates.join(', ') + ' 或更多）。取消勾选某个工具后，该工具不再被拦截。'),
        React.createElement('div', { className: 'cq-tools' },
          candidates.map((name) => React.createElement('label', { className: 'cq-row', key: name },
            React.createElement('input', {
              type: 'checkbox',
              checked: toolChecked(name),
              disabled: busy || !cfg.interceptTools,
              onChange: () => toggleTool(name),
            }),
            name,
          )),
        ),
      ),
      React.createElement('div', { className: 'cq-section' },
        React.createElement('div', { className: 'cq-section-title' }, '审查 Review'),
        React.createElement('label', { className: 'cq-row' },
          React.createElement('input', {
            type: 'checkbox',
            checked: !!cfg.llmReview,
            disabled: busy,
            onChange: () => save({ llmReview: !cfg.llmReview }),
          }),
          '启用 LLM 审查子 Agent',
        ),
        React.createElement('div', { className: 'cq-hint' }, '关闭后 request_review 仅执行确定性规则审查（语法 + 危险模式 + 越界路径）。'),
        React.createElement('div', { className: 'cq-row' }, '审查员模型：'),
        React.createElement('label', { className: 'cq-row' },
          React.createElement('input', {
            type: 'radio',
            name: 'cq-reviewer-mode',
            checked: cfg.reviewerMode === 'follow-session' || cfg.reviewerMode === undefined,
            disabled: busy,
            onChange: () => save({ reviewerMode: 'follow-session' }),
          }),
          '跟随会话',
        ),
        React.createElement('label', { className: 'cq-row' },
          React.createElement('input', {
            type: 'radio',
            name: 'cq-reviewer-mode',
            checked: cfg.reviewerMode === 'custom',
            disabled: busy,
            onChange: () => save({ reviewerMode: 'custom' }),
          }),
          '自定义模型',
        ),
        cfg.reviewerMode === 'custom' ? React.createElement('div', { className: 'cq-row' },
          React.createElement('select', {
            className: 'cq-select',
            value: cfg.reviewerProvider || '',
            disabled: busy,
            onChange: (ev) => {
              const provider = ev.target.value
              save({ reviewerProvider: provider, reviewerModel: '' })
              loadModels(provider)
            },
          },
            React.createElement('option', { value: '' }, '选择 provider…'),
            providers.map((p) => React.createElement('option', { key: p.id, value: p.id }, p.name || p.id)),
          ),
          React.createElement('select', {
            className: 'cq-select',
            value: cfg.reviewerModel || '',
            disabled: busy || !cfg.reviewerProvider,
            onChange: (ev) => save({ reviewerModel: ev.target.value }),
          },
            React.createElement('option', { value: '' }, '选择 model…'),
            models.map((m) => React.createElement('option', { key: m.id, value: m.id }, m.name || m.id)),
          ),
        ) : null,
      ),
      React.createElement('div', { className: 'cq-section' },
        React.createElement('div', { className: 'cq-section-title' }, '隔离 Isolation'),
        React.createElement('label', { className: 'cq-row' },
          React.createElement('input', {
            type: 'checkbox',
            checked: !!cfg.blockSubagents,
            disabled: busy,
            onChange: () => save({ blockSubagents: !cfg.blockSubagents }),
          }),
          '拦截派生子 Agent',
        ),
        React.createElement('div', { className: 'cq-hint' }, '审查生效时，subagent/subagent_fork/workflow/ralph 调用被拒绝（子代理会重新获得直接执行权）。'),
      ),
      React.createElement('div', { className: 'cq-section' },
        React.createElement('div', { className: 'cq-section-title' }, '待审批命令 Pending approval'),
        React.createElement('div', { className: 'cq-actions' },
          React.createElement('span', { className: 'cq-actionsSpacer' }),
          React.createElement('button', { className: 'cq-btn ghost', disabled: busy, onClick: refreshPending }, '刷新'),
        ),
        pendingRows.length > 0 ? pendingRows : React.createElement('div', { className: 'cq-hint' }, '暂无待审批命令。'),
      ),
      msg ? React.createElement('div', { className: 'cq-msg' }, msg) : null,
    )
  }

  return React.createElement('li', { className: 'cq-card' + (open ? ' cq-cardOpen' : '') },
    header,
    open ? body : null,
  )
}

/* Composer-row per-session switch (styled like the access-mode control). */
function SessionSwitch(props) {
  const [cfg, setCfg] = React.useState(null)
  const [pending, setPending] = React.useState([])
  const [open, setOpen] = React.useState(false)
  const [busy, setBusy] = React.useState(false)
  const sessionId = props && props.sessionId ? String(props.sessionId) : ''

  function load() {
    host.call('config.get').then((c) => {
      if (c && !c.error) setCfg(c)
    }).catch(() => {})
    host.call('pending.list').then((r) => {
      if (r && Array.isArray(r.pending)) setPending(r.pending)
    }).catch(() => {})
  }

  React.useEffect(() => {
    load()
    return () => {}
  }, [sessionId])

  function setReviewed(next) {
    setBusy(true)
    host.call('session.set', { sessionId, reviewed: next }).then((r) => {
      setBusy(false)
      setOpen(false)
      if (r && r.ok) {
        setCfg((prev) => Object.assign({}, prev, { reviewScope: r.reviewScope, reviewedSessions: r.reviewedSessions }))
      }
    }).catch((e) => {
      setBusy(false)
      setOpen(false)
    })
  }

  if (cfg === null) {
    return React.createElement('button', { className: 'cq-session-btn', disabled: true }, '隔离 …')
  }

  const globalOn = cfg.reviewScope === 'global' || cfg.reviewScope === undefined
  const reviewed = Array.isArray(cfg.reviewedSessions) && cfg.reviewedSessions.indexOf(sessionId) !== -1
  const on = globalOn || (cfg.reviewScope === 'per-session' && reviewed)

  const btn = React.createElement('button', {
    className: 'cq-session-btn' + (on ? ' on' : ''),
    disabled: globalOn || busy,
    title: globalOn ? '全局审查已启用' : (on ? '本会话审查已开启' : '本会话审查未开启'),
    onClick: () => setOpen(!open),
  },
    React.createElement('span', { className: 'cq-session-dot' }),
    on ? '隔离 开' : '隔离 关',
    pending.length > 0 ? '（' + pending.length + '）' : null,
  )

  if (globalOn) return btn

  const menu = open ? React.createElement('div', { className: 'cq-session-menu' },
    React.createElement('div', { className: 'cq-session-menu-title' }, '命令隔离 · 本会话'),
    React.createElement('div', { className: 'cq-row' },
      React.createElement('span', { className: 'cq-session-dot' }),
      on ? '本会话审查已开启' : '本会话审查未开启',
    ),
    pending.length > 0 ? React.createElement('div', { className: 'cq-hint' }, '待审批命令：' + pending.length + '（见设置 → 插件 → Command Quarantine）') : null,
    on
      ? React.createElement('button', { className: 'cq-btn ghost', disabled: busy, onClick: () => setReviewed(false) }, '关闭本会话审查')
      : React.createElement('button', { className: 'cq-btn primary', disabled: busy, onClick: () => setReviewed(true) }, '开启本会话审查'),
    React.createElement('div', { className: 'cq-warn' }, '关闭后，本会话及其派生的子代理都不会被拦截（若需恢复，可再次开启）。'),
  ) : null

  return React.createElement('div', { className: 'cq-session-wrap' }, btn, menu)
}

return {
  apply(ctx) {
    const slots = ctx.get('slots')
    if (slots === undefined) return
    styles.insert(CSS)
    slots.inject('settings.plugin.item', () => slots.register(
      { name: 'settings.plugin.item', id: 'command-quarantine', order: 30, label: 'Command Quarantine' },
      () => React.createElement(SettingsCard),
    ))
    slots.inject('conversation.input.left', () => slots.register(
      { name: 'conversation.input.left', id: 'command-quarantine-session', order: 10, label: 'Command Quarantine session switch' },
      (props) => React.createElement(SessionSwitch, { sessionId: props.sessionId }),
    ))
  },
}
