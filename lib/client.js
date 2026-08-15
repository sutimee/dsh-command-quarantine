/**
 * DSH Command Quarantine — client half (composition bundle)
 * =====================================================================
 * A classic script registered through `window.__ModuleLoader__.load` (the
 * composition client-module system). Two UI surfaces, both in the shipped
 * DSH visual language (--dsw-alias-*):
 *
 * 1. Settings → Plugins → Command Quarantine: a collapsible PluginCard-style
 *    entry with layered review scope (global / per-session / off), the
 *    intercepted-tool checklist, the LLM reviewer options, the delegation
 *    guard. The card is a STAGED FORM in the
 *    native pattern: every control edits a local draft; nothing is written
 *    until 保存, and 取消 discards the draft.
 * 2. Composer row (conversation.input.left): a small per-session switch
 *    styled like the access-mode control. Greyed out while global review is
 *    on; otherwise toggles whether THIS session (and its subagent lineage)
 *    is intercepted.
 *
 * All state lives in the machine-level settings document
 * ($DSH_HOME/settings.yaml, namespace `command-quarantine`), reached through
 * the native `ctx.settingsScope` binder. The host half answers panel actions
 * (approve/reject) and model lists through the same namespace
 * (modelRequest → modelResponse).
 */

window.__ModuleLoader__.load({
  id: "@sutang/dsh-command-quarantine",
  factory: function (require) {
    var module = { exports: {} }
    var exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" })
    var React = require("react")

    var CSS = [
      ".cq-card { list-style: none; border: 1px solid var(--dsw-alias-border-l2); border-radius: 12px; background: var(--dsw-alias-bg-layer-3); transition: border-color .16s, background .16s; }",
      ".cq-card:hover { border-color: var(--dsw-alias-label-dimmed); }",
      ".cq-cardOpen { background: var(--dsw-alias-bg-layer-2); border-color: var(--dsw-alias-label-dimmed); }",
      ".cq-header { width: 100%; appearance: none; border: 0; background: none; font: inherit; color: inherit; text-align: left; cursor: pointer; display: flex; align-items: center; gap: 12px; padding: 14px 16px; border-radius: 12px; }",
      ".cq-header:focus-visible { outline: 2px solid var(--dsw-alias-brand-primary); outline-offset: -2px; }",
      ".cq-headText { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 4px; }",
      ".cq-name { font-size: 15px; font-weight: 600; line-height: 1.4; color: var(--dsw-alias-label-primary); }",
      ".cq-description { font-size: 13px; line-height: 1.5; color: var(--dsw-alias-label-tertiary); }",
      ".cq-chevron { flex: none; color: var(--dsw-alias-label-tertiary); transition: transform .16s; font-size: 12px; }",
      ".cq-chevronOpen { transform: rotate(180deg); }",
      ".cq-pending { flex: none; border-radius: 999px; padding: 1px 8px; font-size: 11px; line-height: 17px; font-weight: 500; white-space: nowrap; background: var(--dsw-alias-bg-module-platform); color: var(--dsw-alias-label-secondary); }",
      ".cq-body { border-top: 1px solid var(--dsw-alias-border-l2); margin: 0 16px; padding: 4px 0 12px; display: flex; flex-direction: column; gap: 14px; font-size: 13px; line-height: 1.5; }",
      ".cq-section { padding-top: 12px; display: flex; flex-direction: column; gap: 8px; }",
      ".cq-section + .cq-section { border-top: 1px solid var(--dsw-alias-border-l2); }",
      ".cq-section-title { font-size: 12px; font-weight: 600; line-height: 1.5; color: var(--dsw-alias-label-tertiary); }",
      ".cq-row { display: flex; align-items: center; gap: 8px; color: var(--dsw-alias-label-primary); }",
      ".cq-row input[type=\"checkbox\"], .cq-row input[type=\"radio\"] { margin: 0; accent-color: var(--dsw-alias-brand-primary); }",
      ".cq-hint { font-size: 12px; line-height: 1.5; color: var(--dsw-alias-label-tertiary); }",
      ".cq-warn { font-size: 12px; line-height: 1.5; color: var(--dsw-alias-label-error); }",
      ".cq-tools { display: flex; flex-direction: column; gap: 2px; max-height: 160px; overflow: auto; }",
      ".cq-subblock { border: 1px solid var(--dsw-alias-border-l2); border-radius: 10px; padding: 10px 12px; display: flex; flex-direction: column; gap: 8px; background: var(--dsw-alias-bg-layer-3); }",
      ".cq-subblock-active { border-color: var(--dsw-alias-brand-primary); background: var(--dsw-alias-bg-layer-2); }",
      ".cq-select { appearance: none; padding: 5px 10px; border-radius: 8px; border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); font: inherit; font-size: 13px; max-width: 100%; }",
      ".cq-select:disabled { opacity: 0.4; cursor: default; }",
      ".cq-pending-item { border: 1px solid var(--dsw-alias-border-l2); border-radius: 10px; padding: 10px; display: flex; flex-direction: column; gap: 6px; background: var(--dsw-alias-bg-layer-3); }",
      ".cq-pending-meta { display: flex; gap: 8px; flex-wrap: wrap; font-size: 12px; color: var(--dsw-alias-label-tertiary); }",
      ".cq-pending-reason { font-size: 12px; line-height: 1.5; color: var(--dsw-alias-label-secondary); white-space: pre-wrap; max-height: 72px; overflow: auto; }",
      ".cq-actions { display: flex; align-items: center; gap: 8px; }",
      ".cq-actionsSpacer { flex: 1; }",
      ".cq-btn { appearance: none; border: 1px solid transparent; border-radius: 8px; padding: 5px 14px; font: inherit; font-size: 13px; line-height: 1.5; cursor: pointer; }",
      ".cq-btn.ghost { border-color: var(--dsw-alias-border-l2); background: none; color: var(--dsw-alias-label-secondary); }",
      ".cq-btn.ghost:hover:not(:disabled) { color: var(--dsw-alias-label-primary); border-color: var(--dsw-alias-label-dimmed); }",
      ".cq-btn.primary { background: var(--dsw-alias-brand-primary); color: #fff; }",
      ".cq-btn.danger { border-color: var(--dsw-alias-label-error); background: none; color: var(--dsw-alias-label-error); }",
      ".cq-btn.danger:hover:not(:disabled) { border-color: var(--dsw-alias-label-error); color: var(--dsw-alias-label-error); background: var(--dsw-alias-bg-layer-3); }",
      ".cq-btn:disabled { opacity: 0.4; cursor: default; }",
      ".cq-btn:focus-visible { outline: 2px solid var(--dsw-alias-brand-primary); outline-offset: 1px; }",
      ".cq-msg { font-size: 12px; line-height: 1.5; color: var(--dsw-alias-label-secondary); white-space: pre-wrap; word-break: break-word; }",
      ".cq-footer { display: flex; align-items: center; gap: 8px; padding-top: 12px; border-top: 1px solid var(--dsw-alias-border-l2); }",
      ".cq-dirtyHint { font-size: 12px; line-height: 1.5; color: var(--dsw-alias-label-tertiary); }",
      ".cq-audit { display: flex; flex-direction: column; gap: 6px; padding: 16px; height: 100%; overflow: auto; }",
      ".cq-audit-row { display: flex; gap: 10px; align-items: flex-start; border-bottom: 1px solid var(--dsw-alias-border-l2); padding: 7px 0; font-size: 12px; line-height: 1.5; }",
      ".cq-audit-ts { flex: none; color: var(--dsw-alias-label-tertiary); white-space: nowrap; }",
      ".cq-audit-ev { flex: none; border-radius: 999px; padding: 0 8px; font-size: 11px; line-height: 17px; font-weight: 500; background: var(--dsw-alias-bg-module-platform); color: var(--dsw-alias-label-secondary); white-space: nowrap; }",
      ".cq-audit-body { flex: 1; min-width: 0; color: var(--dsw-alias-label-primary); word-break: break-word; }",
      ".cq-audit-meta { color: var(--dsw-alias-label-tertiary); }",
      ".cq-audit-empty { color: var(--dsw-alias-label-tertiary); font-size: 13px; padding: 24px; text-align: center; }",
      ".cq-audit-card { border: 1px solid var(--dsw-alias-border-l2); border-radius: 10px; padding: 10px 12px; background: var(--dsw-alias-bg-layer-3); display: flex; flex-direction: column; gap: 6px; }",
      ".cq-audit-cardhead { display: flex; align-items: center; gap: 8px; }",
      ".cq-audit-intent { flex: 1; min-width: 0; color: var(--dsw-alias-label-primary); font-weight: 500; }",
      ".cq-audit-status { border-radius: 999px; padding: 0 8px; font-size: 11px; line-height: 17px; background: var(--dsw-alias-bg-module-platform); color: var(--dsw-alias-brand-primary); white-space: nowrap; }",
      ".cq-audit-cardmeta { font-size: 11px; color: var(--dsw-alias-label-tertiary); }",
      ".cq-audit-evrow { display: flex; align-items: flex-start; gap: 8px; flex-wrap: wrap; padding: 3px 0; }",
      ".cq-audit-actor { flex: none; color: var(--dsw-alias-label-secondary); }",
      ".cq-audit-reason { flex-basis: 100%; color: var(--dsw-alias-label-tertiary); font-size: 12px; }",
      ".cq-session-wrap { position: relative; display: inline-flex; }",
      ".cq-session-btn { appearance: none; border: 1px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-secondary); border-radius: 999px; padding: 3px 10px; font: inherit; font-size: 12px; line-height: 18px; cursor: pointer; display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; }",
      ".cq-session-btn:hover:not(:disabled) { color: var(--dsw-alias-label-primary); border-color: var(--dsw-alias-label-dimmed); }",
      ".cq-session-btn.on { color: var(--dsw-alias-brand-primary); border-color: var(--dsw-alias-brand-primary); }",
      ".cq-session-btn:disabled { opacity: 0.5; cursor: default; }",
      ".cq-session-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }",
      ".cq-session-menu { position: absolute; bottom: calc(100% + 6px); left: 0; z-index: 40; min-width: 260px; border: 1px solid var(--dsw-alias-border-l2); border-radius: 10px; background: var(--dsw-alias-bg-layer-2); box-shadow: 0 8px 24px rgba(0, 0, 0, 0.16); padding: 10px; display: flex; flex-direction: column; gap: 8px; font-size: 13px; line-height: 1.5; color: var(--dsw-alias-label-primary); }",
      ".cq-session-menu-title { font-size: 12px; font-weight: 600; color: var(--dsw-alias-label-tertiary); }",
      ".cq-session-menu-row { display: flex; align-items: center; gap: 8px; }",
    ].join("\n")

    function useSection(scope) {
      /* Bound-style wrappers: React invokes these as plain functions, so a
       * bare `scope.subscribe` would lose its `this` and crash on render. */
      var subscribe = function (listener) { return scope.subscribe(listener) }
      var getSnapshot = function () { return scope.getSnapshot() }
      return React.useSyncExternalStore(subscribe, getSnapshot)
    }

    function sectionValue(snap) {
      if (!snap || snap.status !== "ready" && snap.status !== "loading") return undefined
      return snap.value
    }

    /* Fields this card edits; everything else in the namespace is host-managed. */
    var OWNED_FIELDS = [
      "reviewScope", "reviewMode", "reviewerMode", "reviewerProvider",
      "reviewerModel", "blockSubagents", "interceptTools", "toolDenyList",
      "quarantineRoot", "reviewerReadOutside", "reviewerPersist",
      "reviewerCompactEvery", "projectReadOutside",
      "projectReviewerPersist", "projectCompactEvery",
    ]

    function SettingsCard(props) {
      var scope = props.scope
      var snap = useSection(scope)
      var section = sectionValue(snap)
      var _openState = React.useState(false)
      var open = _openState[0]
      var setOpen = _openState[1]
      var _draftState = React.useState(null)
      var draft = _draftState[0]
      var setDraft = _draftState[1]
      var _msgState = React.useState("")
      var msg = _msgState[0]
      var setMsg = _msgState[1]
      var _busyState = React.useState(false)
      var busy = _busyState[0]
      var setBusy = _busyState[1]
      var _modelState = React.useState({ nonce: 0, models: [] })
      var modelState = _modelState[0]
      var setModelState = _modelState[1]

      /* Watch host answers (modelResponse) as they land. */
      React.useEffect(function () {
        if (!section) return
        if (section.modelResponse && section.modelResponse.nonce && section.modelResponse.nonce === modelState.nonce) {
          setModelState(function (prev) { return { nonce: prev.nonce, models: section.modelResponse.models || [] } })
        }
      }, [snap])

      /* The namespace is not exposed to this browser (api-proxy whitelist). */
      if (!section && snap && snap.status === "unavailable") {
        return React.createElement("li", { className: "cq-card" },
          React.createElement("button", {
            type: "button",
            className: "cq-header",
            "aria-expanded": open,
            onClick: function () { setOpen(!open) },
          },
            React.createElement("span", { className: "cq-headText" },
              React.createElement("span", { className: "cq-name" }, "Command Quarantine"),
              React.createElement("span", { className: "cq-description" }, "配置命名空间未向浏览器暴露"),
            ),
            React.createElement("span", { className: "cq-chevron" + (open ? " cq-chevronOpen" : "") }, "▾"),
          ),
          open ? React.createElement("div", { className: "cq-body" },
            React.createElement("div", { className: "cq-warn" }, "settings 命名空间 command-quarantine 未在 api-proxy 的 Web 白名单中，浏览器无法读取配置。请确认部署补丁（WEB_SETTINGS_NAMESPACES 含 command-quarantine）已随服务器重启加载。"),
          ) : null,
        )
      }

      if (!section) {
        return React.createElement("li", { className: "cq-card" },
          React.createElement("button", { className: "cq-header", disabled: true },
            React.createElement("span", { className: "cq-headText" },
              React.createElement("span", { className: "cq-name" }, "Command Quarantine"),
              React.createElement("span", { className: "cq-description" }, "正在读取配置…"),
            ),
          ),
        )
      }

      var candidates = Array.isArray(section.toolCandidates) ? section.toolCandidates : []
      var providers = Array.isArray(section.providers) ? section.providers : []

      /* Staged-form helpers: effective value = draft (when a draft exists and
       * owns the field) over the stored section. Nothing is written until 保存. */
      function eff(field) {
        if (draft !== null && draft !== undefined && Object.prototype.hasOwnProperty.call(draft, field)) return draft[field]
        return section[field]
      }

      function stage(patch) {
        var base = {}
        if (draft !== null && draft !== undefined) {
          for (var k in draft) {
            if (Object.prototype.hasOwnProperty.call(draft, k)) base[k] = draft[k]
          }
        } else {
          for (var i = 0; i < OWNED_FIELDS.length; i++) base[OWNED_FIELDS[i]] = section[OWNED_FIELDS[i]]
        }
        for (var k2 in patch) {
          if (Object.prototype.hasOwnProperty.call(patch, k2)) base[k2] = patch[k2]
        }
        setDraft(base)
        setMsg("")
      }

      function dirtyFields() {
        var out = []
        for (var i = 0; i < OWNED_FIELDS.length; i++) {
          var f = OWNED_FIELDS[i]
          if (JSON.stringify(eff(f)) !== JSON.stringify(section[f])) out.push(f)
        }
        return out
      }

      /* Settings writes can race the Host's own mirror commits and be dropped
       * silently (revision-fenced mutate). Write, then read back: retry a few
       * times until the value sticks, and report when it never does. */
      function setWithRetry(field, value, onFail, attempts) {
        scope.set(field, value)
        var tries = attempts === undefined ? 3 : attempts
        window.setTimeout(function () {
          var snap2 = scope.getSnapshot()
          var v = snap2 && snap2.value ? snap2.value[field] : undefined
          if (v !== undefined && JSON.stringify(v) === JSON.stringify(value)) return
          if (tries <= 1) {
            if (onFail) onFail()
            return
          }
          setWithRetry(field, value, onFail, tries - 1)
        }, 500)
      }

      var dirty = dirtyFields()

      function discard() {
        setDraft(null)
        setMsg("")
      }

      function save() {
        var fields = dirtyFields()
        if (fields.length === 0) return
        setBusy(true)
        for (var i = 0; i < fields.length; i++) {
          scope.set(fields[i], eff(fields[i]))
        }
        /* Keep the legacy llmReview alias in sync with the three-way mode
         * (host migration reads it for pre-v1.4 installs). */
        if (fields.indexOf("reviewMode") !== -1) {
          scope.set("llmReview", eff("reviewMode") !== "rules")
        }
        setDraft(null)
        setMsg("已保存，设置已生效")
        window.setTimeout(function () { setBusy(false) }, 800)
      }

      function toggleTool(name) {
        var enabled = eff("toolDenyList")
        enabled = Array.isArray(enabled) && enabled.length > 0 ? enabled.slice() : candidates.slice()
        var idx = enabled.indexOf(name)
        var next
        if (idx === -1) next = enabled.concat([name])
        else {
          next = enabled.filter(function (n) { return n !== name })
          if (next.length === candidates.length) next = [] /* all selected → auto default */
        }
        stage({ toolDenyList: next })
      }

      function pickProvider(provider) {
        stage({ reviewerProvider: provider, reviewerModel: "" })
        if (provider) {
          var nonce = Date.now()
          setModelState({ nonce: nonce, models: [] })
          setWithRetry("modelRequest", { provider: provider, nonce: nonce })
        } else {
          setModelState({ nonce: 0, models: [] })
        }
      }

      function toolChecked(name) {
        var denyList = eff("toolDenyList")
        denyList = Array.isArray(denyList) ? denyList : []
        return denyList.length === 0 ? candidates.indexOf(name) !== -1 : denyList.indexOf(name) !== -1
      }

      /* Ensure the currently selected model always appears in the dropdown,
       * even before the host model list arrives (fresh page load). */
      var modelOptions = modelState.models
      var curModel = eff("reviewerModel")
      if (curModel && !modelState.models.some(function (m) { return m.id === curModel })) {
        modelOptions = modelState.models.concat([{ id: curModel, name: curModel }])
      }

      var header = React.createElement("button", {
        type: "button",
        className: "cq-header",
        "aria-expanded": open,
        onClick: function () { setOpen(!open) },
      },
        React.createElement("span", { className: "cq-headText" },
          React.createElement("span", { className: "cq-name" }, "Command Quarantine"),
          React.createElement("span", { className: "cq-description" }, "命令隔离区：拦截直接命令执行；命令经提交 → 审查 → 按 ID 执行，全程审计。"),
        ),
        React.createElement("span", { className: "cq-chevron" + (open ? " cq-chevronOpen" : "") }, "▾"),
      )

      var body = React.createElement("div", { className: "cq-body" },
        React.createElement("div", { className: "cq-section" },
          React.createElement("div", { className: "cq-section-title" }, "审查范围 Review scope"),
          React.createElement("label", { className: "cq-row" },
            React.createElement("input", {
              type: "radio", name: "cq-review-scope",
              checked: eff("reviewScope") === "global" || eff("reviewScope") === undefined,
              disabled: busy,
              onChange: function () { stage({ reviewScope: "global" }) },
            }),
            "全局审查",
          ),
          React.createElement("div", { className: "cq-hint" }, "所有会话、所有模型与 agent 预设、所有子代理的命令执行都被拦截（输入框底部的会话开关将置灰）。"),
          React.createElement("label", { className: "cq-row" },
            React.createElement("input", {
              type: "radio", name: "cq-review-scope",
              checked: eff("reviewScope") === "per-session",
              disabled: busy,
              onChange: function () { stage({ reviewScope: "per-session" }) },
            }),
            "按会话审查",
          ),
          React.createElement("div", { className: "cq-hint" }, "默认不审查；在输入框底部的开关中为单个会话开启，其子代理按血缘一并拦截。"),
          React.createElement("label", { className: "cq-row" },
            React.createElement("input", {
              type: "radio", name: "cq-review-scope",
              checked: eff("reviewScope") === "off",
              disabled: busy,
              onChange: function () { stage({ reviewScope: "off" }) },
            }),
            "关闭审查",
          ),
          React.createElement("div", { className: "cq-warn" }, "所有会话（含子代理）都不再拦截任何命令执行——请确认这是你有意的选择。"),
        ),
        React.createElement("div", { className: "cq-section" },
          React.createElement("div", { className: "cq-section-title" }, "受拦截工具 Intercepted tools"),
          React.createElement("label", { className: "cq-row" },
            React.createElement("input", {
              type: "checkbox",
              checked: !!eff("interceptTools"),
              disabled: busy,
              onChange: function () { stage({ interceptTools: !eff("interceptTools") }) },
            }),
            "拦截命令执行工具",
          ),
          React.createElement("div", { className: "cq-hint" }, "拦截按工具名称启发式匹配（当前候选：" + candidates.join(", ") + "）。取消勾选某个工具后，该工具不再被拦截。"),
          React.createElement("div", { className: "cq-tools" },
            candidates.map(function (name) {
              return React.createElement("label", { className: "cq-row", key: name },
                React.createElement("input", {
                  type: "checkbox",
                  checked: toolChecked(name),
                  disabled: busy || !eff("interceptTools"),
                  onChange: function () { toggleTool(name) },
                }),
                name,
              )
            }),
          ),
        ),
        React.createElement("div", { className: "cq-section" },
          React.createElement("div", { className: "cq-section-title" }, "审查 Review"),
          React.createElement("div", { className: "cq-subblock" + (eff("reviewMode") === "rules" ? " cq-subblock-active" : "") },
            React.createElement("label", { className: "cq-row" },
              React.createElement("input", {
                type: "radio", name: "cq-review-mode",
                checked: eff("reviewMode") === "rules",
                disabled: busy,
                onChange: function () { stage({ reviewMode: "rules" }) },
              }),
              "不开启（仅规则筛查）",
            ),
            React.createElement("div", { className: "cq-hint" }, "只做程序化筛查：语法、危险指令黑名单、转义/引号/括号闭合、越界路径；不派生子 Agent，零 token。"),
          ),
          React.createElement("div", { className: "cq-subblock" + (eff("reviewMode") !== "rules" && eff("reviewMode") !== "project" ? " cq-subblock-active" : "") },
            React.createElement("label", { className: "cq-row" },
              React.createElement("input", {
                type: "radio", name: "cq-review-mode",
                checked: eff("reviewMode") !== "rules" && eff("reviewMode") !== "project",
                disabled: busy,
                onChange: function () { stage({ reviewMode: "command" }) },
              }),
              "审查员 Agent",
            ),
            React.createElement("div", { className: "cq-hint" }, "轻量子 Agent：判断命令作用与危险程度、识别提示词注入；提示词精简，成本低，可同会话复用。"),
            React.createElement("label", { className: "cq-row" },
              React.createElement("input", {
                type: "checkbox",
                checked: !!eff("reviewerReadOutside"),
                disabled: busy || eff("reviewMode") === "rules",
                onChange: function () { stage({ reviewerReadOutside: !eff("reviewerReadOutside") }) },
              }),
              "允许审查员读取工作区外文件",
            ),
            React.createElement("div", { className: "cq-hint" }, "帮助审查员复核校验命令涉及的工作区外目标（依赖、配置、被引用脚本），建议开启。"),
            React.createElement("label", { className: "cq-row" },
              React.createElement("input", {
                type: "checkbox",
                checked: !!eff("reviewerPersist"),
                disabled: busy || eff("reviewMode") !== "command",
                onChange: function () { stage({ reviewerPersist: !eff("reviewerPersist") }) },
              }),
              "同会话复用审查员",
            ),
            React.createElement("div", { className: "cq-row" },
              "每 ",
              React.createElement("input", {
                type: "number",
                min: 1,
                max: 20,
                className: "cq-select",
                value: String(eff("reviewerCompactEvery") === undefined || eff("reviewerCompactEvery") === null ? 10 : eff("reviewerCompactEvery")),
                disabled: busy || eff("reviewMode") !== "command",
                onChange: function (ev) {
                  var n = Math.floor(Number(ev.target.value))
                  if (!(n >= 1)) n = 1
                  if (n > 20) n = 20
                  stage({ reviewerCompactEvery: n })
                },
              }),
              " 次审查后自动压缩其上下文（与 /compact 同机制）",
            ),
            React.createElement("div", { className: "cq-hint" }, "复用让审查员保留记忆（省 token、增强拆分攻击识别），定期压缩控制上下文体积；关闭则每次新建。"),
          ),
          React.createElement("div", { className: "cq-subblock" + (eff("reviewMode") === "project" ? " cq-subblock-active" : "") },
            React.createElement("label", { className: "cq-row" },
              React.createElement("input", {
                type: "radio", name: "cq-review-mode",
                checked: eff("reviewMode") === "project",
                disabled: busy,
                onChange: function () { stage({ reviewMode: "project" }) },
              }),
              "项目审查员",
            ),
            React.createElement("div", { className: "cq-hint" }, "包含审查员全部能力，另注入项目上下文并做项目级影响分析，高影响命令必须给出备份/回滚建议。⚠ 每条命令都注入项目上下文，费 token，请只在需要时开启。"),
            React.createElement("label", { className: "cq-row" },
              React.createElement("input", {
                type: "checkbox",
                checked: !!eff("projectReadOutside"),
                disabled: busy || eff("reviewMode") !== "project",
                onChange: function () { stage({ projectReadOutside: !eff("projectReadOutside") }) },
              }),
              "允许项目审查员读取工作区外文件",
            ),
            React.createElement("div", { className: "cq-hint" }, "帮助项目审查员核对项目外的依赖与配置，按需开启。"),
            React.createElement("label", { className: "cq-row" },
              React.createElement("input", {
                type: "checkbox",
                checked: !!eff("projectReviewerPersist"),
                disabled: busy || eff("reviewMode") !== "project",
                onChange: function () { stage({ projectReviewerPersist: !eff("projectReviewerPersist") }) },
              }),
              "同会话复用项目审查员",
            ),
            React.createElement("div", { className: "cq-row" },
              "每 ",
              React.createElement("input", {
                type: "number",
                min: 1,
                max: 100,
                className: "cq-select",
                value: String(eff("projectCompactEvery") === undefined || eff("projectCompactEvery") === null ? 10 : eff("projectCompactEvery")),
                disabled: busy || eff("reviewMode") !== "project",
                onChange: function (ev) {
                  var n = Math.floor(Number(ev.target.value))
                  if (!(n >= 1)) n = 1
                  if (n > 100) n = 100
                  stage({ projectCompactEvery: n })
                },
              }),
              " 次审查后自动压缩其上下文（与 /compact 同机制）",
            ),
            React.createElement("div", { className: "cq-hint" }, "复用让项目审查员保留记忆（省 token、增强拆分攻击识别），定期压缩控制上下文体积；关闭则每次新建。"),
          ),
          React.createElement("div", { className: "cq-hint" }, "两个审查员的工作区内读取始终自由（无需审批、无次数限制）；仅越界读取本身不会导致人工审批。"),
          React.createElement("div", { className: "cq-row" }, "审查员模型："),
          React.createElement("label", { className: "cq-row" },
            React.createElement("input", {
              type: "radio", name: "cq-reviewer-mode",
              checked: eff("reviewerMode") === "follow-session" || eff("reviewerMode") === undefined,
              disabled: busy || eff("reviewMode") === "rules",
              onChange: function () { stage({ reviewerMode: "follow-session" }) },
            }),
            "跟随会话",
          ),
          React.createElement("label", { className: "cq-row" },
            React.createElement("input", {
              type: "radio", name: "cq-reviewer-mode",
              checked: eff("reviewerMode") === "custom",
              disabled: busy || eff("reviewMode") === "rules",
              onChange: function () { stage({ reviewerMode: "custom" }) },
            }),
            "自定义模型",
          ),
          eff("reviewerMode") === "custom" && eff("reviewMode") !== "rules" ? React.createElement("div", { className: "cq-row" },
            React.createElement("select", {
              className: "cq-select",
              value: eff("reviewerProvider") || "",
              disabled: busy,
              onChange: function (ev) { pickProvider(ev.target.value) },
            },
              React.createElement("option", { value: "" }, "选择 provider…"),
              providers.map(function (p) { return React.createElement("option", { key: p.id, value: p.id }, p.name || p.id) }),
            ),
            React.createElement("select", {
              className: "cq-select",
              value: eff("reviewerModel") || "",
              disabled: busy || !eff("reviewerProvider"),
              onChange: function (ev) { stage({ reviewerModel: ev.target.value }) },
            },
              React.createElement("option", { value: "" }, "选择 model…"),
              modelOptions.map(function (m) { return React.createElement("option", { key: m.id, value: m.id }, m.name || m.id) }),
            ),
          ) : null,
        ),
        React.createElement("div", { className: "cq-section" },
          React.createElement("div", { className: "cq-section-title" }, "隔离 Isolation"),
          React.createElement("label", { className: "cq-row" },
            React.createElement("input", {
              type: "checkbox",
              checked: !!eff("blockSubagents"),
              disabled: busy,
              onChange: function () { stage({ blockSubagents: !eff("blockSubagents") }) },
            }),
            "拦截派生子 Agent",
          ),
          React.createElement("div", { className: "cq-hint" }, "审查生效时，subagent/subagent_fork/workflow/ralph 调用被拒绝（子代理会重新获得直接执行权）。"),
          React.createElement("div", { className: "cq-row" }, "隔离数据目录："),
          React.createElement("input", {
            type: "text",
            className: "cq-select",
            value: eff("quarantineRoot") || "",
            placeholder: section.resolvedStorageRoot || "默认位置",
            disabled: busy,
            onChange: function (ev) { stage({ quarantineRoot: ev.target.value }) },
          }),
          React.createElement("div", { className: "cq-hint" }, "留空 = " + (section.resolvedStorageRoot || "默认位置") + "。修改后新命令写入新目录，历史记录仍可读。目录位于工作区之外，沙箱命令与文件工具都无法篡改审计证据。"),
        ),
        msg ? React.createElement("div", { className: "cq-msg" }, msg) : null,
        React.createElement("div", { className: "cq-footer" },
          React.createElement("span", { className: "cq-dirtyHint" }, "更改在保存后生效"),
          React.createElement("span", { className: "cq-actionsSpacer" }),
          React.createElement("button", { className: "cq-btn ghost", disabled: busy || !dirty, onClick: discard }, "取消"),
          React.createElement("button", { className: "cq-btn primary", disabled: busy || !dirty, onClick: save }, "保存"),
        ),
      )

      return React.createElement("li", { className: "cq-card" + (open ? " cq-cardOpen" : "") },
        header,
        open ? body : null,
      )
    }

    /* CQ审计: the conversation view tab listing this conversation's
     * quarantine audit trail. Data comes from the plugin's own HTTP endpoint
     * (/plugins/command-quarantine/audit?session=…) served by the host's
     * webServer route — NOT from the settings document, which stays pure
     * configuration. Polls every 4s while mounted; oldest card first,
     * newest visible at the tab's auto-scrolled bottom. */
    function fmtTs(ts) {
      var d = new Date(ts)
      if (isNaN(d.getTime())) return String(ts || '')
      return d.toLocaleString()
    }

    function evLabel(ev) {
      switch (ev) {
        case 'SUBMIT': return '提交'
        case 'REVIEW': return '审查'
        case 'APPROVE': return '批准'
        case 'REJECT': return '拒绝'
        case 'EXECUTE': return '执行'
        case 'COMPLETE': return '完成'
        default: return String(ev || '')
      }
    }

    function actorLabel(a) {
      switch (a) {
        case 'main-agent': return '主代理'
        case 'deterministic-reviewer': return '确定性审查'
        case 'llm-reviewer': return 'LLM 审查员'
        case 'quarantine-executor': return '执行器'
        case 'user': return '用户'
        default: return String(a || '')
      }
    }

    function statusLabel(s) {
      switch (s) {
        case 'PENDING': return '待审查'
        case 'UNDER_REVIEW': return '审查中'
        case 'APPROVED': return '已批准'
        case 'USER_REVIEW': return '待人工'
        case 'EXECUTED': return '已执行'
        case 'REJECTED': return '已拒绝'
        default: return String(s || '')
      }
    }

    function outcomeLabel(o) {
      switch (o) {
        case 'ok': return '正常'
        case 'blocked': return '被拦截'
        case 'error': return '错误'
        case 'timeout': return '超时'
        case 'aborted': return '中止'
        default: return String(o || '')
      }
    }

    /* Fetch + 4s poll against the plugin's audit endpoint. The host answers
     * with the same card projection the tab renders (already filtered to the
     * session); AbortController cancels in-flight polls on unmount. */
    function useAuditFeed(sessionId) {
      var _feedState = React.useState({ cards: [], error: false, loading: true })
      var feed = _feedState[0]
      var setFeed = _feedState[1]
      React.useEffect(function () {
        var alive = true
        var controller
        function load() {
          controller = new AbortController()
          fetch("plugins/command-quarantine/audit?session=" + encodeURIComponent(sessionId), { signal: controller.signal, cache: "no-store" })
            .then(function (r) {
              if (!r.ok) throw new Error("HTTP " + r.status)
              return r.json()
            })
            .then(function (data) {
              if (!alive) return
              setFeed({ cards: Array.isArray(data.cards) ? data.cards : [], error: false, loading: false })
            })
            .catch(function (err) {
              if (!alive) return
              if (err && err.name === "AbortError") return
              setFeed(function (prev) { return { cards: prev.cards, error: true, loading: prev.cards.length === 0 } })
            })
        }
        load()
        var timer = window.setInterval(load, 4000)
        return function () {
          alive = false
          window.clearInterval(timer)
          if (controller) controller.abort()
        }
      }, [sessionId])
      return feed
    }

    function CqAuditView(props) {
      var sessionId = props.sessionId ? String(props.sessionId) : ""
      var feed = useAuditFeed(sessionId)
      if (feed.loading) {
        return React.createElement("div", { className: "cq-audit" },
          React.createElement("div", { className: "cq-audit-empty" }, feed.error ? "审计通道暂不可用（4 秒后自动重试）" : "正在读取隔离区审计日志…"),
        )
      }
      var cards = feed.cards
      /* Belt-and-braces session filter (the host already filters), then the
       * tab's bottom-anchored ordering: oldest first, newest last. */
      if (sessionId !== "") {
        cards = cards.filter(function (c) { return c.session === sessionId })
      }
      cards = cards.slice().sort(function (a, b) { return String(a.submitted_at).localeCompare(String(b.submitted_at)) })
      if (cards.length === 0) {
        return React.createElement("div", { className: "cq-audit" },
          React.createElement("div", { className: "cq-audit-empty" }, "本对话暂无隔离区审计记录"),
        )
      }
      var cardNodes = cards.map(function (c) {
        var evRows = (Array.isArray(c.events) ? c.events : []).map(function (ev, i) {
          var detail = ev.verdict ? "判定 " + ev.verdict + (ev.risk_level ? "（" + ev.risk_level + "）" : "") : ""
          if (ev.exit_code !== undefined && ev.exit_code !== null) detail += (detail ? " · " : "") + "exit " + ev.exit_code
          if (ev.outcome !== undefined && ev.outcome !== null) detail += (detail ? " · " : "") + "结果 " + outcomeLabel(ev.outcome)
          if (ev.duration_ms !== undefined && ev.duration_ms !== null) detail += (detail ? " · " : "") + ev.duration_ms + "ms"
          return React.createElement("div", { className: "cq-audit-evrow", key: "ev" + i },
            React.createElement("span", { className: "cq-audit-ts" }, fmtTs(ev.ts)),
            React.createElement("span", { className: "cq-audit-ev" }, evLabel(ev.event)),
            React.createElement("span", { className: "cq-audit-actor" }, actorLabel(ev.actor)),
            detail ? React.createElement("span", { className: "cq-audit-meta" }, detail) : null,
            ev.reason ? React.createElement("div", { className: "cq-audit-reason" }, ev.reason) : null,
          )
        })
        var st = statusLabel(c.status)
        return React.createElement("div", { className: "cq-audit-card", key: c.id },
          React.createElement("div", { className: "cq-audit-cardhead" },
            React.createElement("div", { className: "cq-audit-intent" }, c.intent || "（无意图说明）"),
            c.tool ? React.createElement("span", { className: "cq-audit-ev" }, c.tool) : null,
            st ? React.createElement("span", { className: "cq-audit-status" }, st) : null,
          ),
          React.createElement("div", { className: "cq-audit-cardmeta" },
            c.id + " · 提交于 " + fmtTs(c.submitted_at),
          ),
          evRows,
        )
      })
      return React.createElement("div", { className: "cq-audit" },
        React.createElement("div", { className: "cq-section-title" }, "隔离区审计（本对话，最新 " + cards.length + " 条命令）"),
        cardNodes,
      )
    }

    /* Composer-row per-session switch (styled like the access-mode control).
     * This is a quick toggle, like the access-mode control: it applies
     * immediately rather than through the card's staged form. */
    function SessionSwitch(props) {
      var scope = props.scope
      var sessionId = props.sessionId ? String(props.sessionId) : ""
      var snap = useSection(scope)
      var section = sectionValue(snap)
      var _openState = React.useState(false)
      var open = _openState[0]
      var setOpen = _openState[1]
      var _busyState = React.useState(false)
      var busy = _busyState[0]
      var setBusy = _busyState[1]

      function setReviewed(next) {
        setBusy(true)
        var list = (Array.isArray(section.reviewedSessions) ? section.reviewedSessions : []).slice()
        var idx = list.indexOf(sessionId)
        if (next && idx === -1) list.push(sessionId)
        if (!next && idx !== -1) list.splice(idx, 1)
        scope.set("reviewedSessions", list)
        if (next && section.reviewScope !== "global" && section.reviewScope !== "per-session") {
          scope.set("reviewScope", "per-session")
        }
        window.setTimeout(function () { setBusy(false); setOpen(false) }, 600)
      }

      if (!section) {
        return React.createElement("button", { className: "cq-session-btn", disabled: true }, "隔离 …")
      }

      var globalOn = section.reviewScope === "global" || section.reviewScope === undefined
      var reviewed = Array.isArray(section.reviewedSessions) && section.reviewedSessions.indexOf(sessionId) !== -1
      var on = globalOn || (section.reviewScope === "per-session" && reviewed)

      var btn = React.createElement("button", {
        className: "cq-session-btn" + (on ? " on" : ""),
        disabled: globalOn || busy,
        title: globalOn ? "全局审查已启用" : (on ? "本会话审查已开启" : "本会话审查未开启"),
        onClick: function () { setOpen(!open) },
      },
        React.createElement("span", { className: "cq-session-dot" }),
        on ? "隔离 开" : "隔离 关",
      )

      if (globalOn) return btn

      var menu = open ? React.createElement("div", { className: "cq-session-menu" },
        React.createElement("div", { className: "cq-session-menu-title" }, "命令隔离 · 本会话"),
        React.createElement("div", { className: "cq-row" },
          React.createElement("span", { className: "cq-session-dot" }),
          on ? "本会话审查已开启" : "本会话审查未开启",
        ),
        on
          ? React.createElement("button", { className: "cq-btn ghost", disabled: busy, onClick: function () { setReviewed(false) } }, "关闭本会话审查")
          : React.createElement("button", { className: "cq-btn primary", disabled: busy, onClick: function () { setReviewed(true) } }, "开启本会话审查"),
        React.createElement("div", { className: "cq-warn" }, "关闭后，本会话及其派生的子代理都不会被拦截（若需恢复，可再次开启）。"),
      ) : null

      return React.createElement("div", { className: "cq-session-wrap" }, btn, menu)
    }

    var PLUGIN_ID = "@sutang/dsh-command-quarantine"

    function apply(ctx) {
      if (typeof document !== "undefined" && document.querySelector("style[data-plugin=" + JSON.stringify(PLUGIN_ID) + "]") === null) {
        var tag = document.createElement("style")
        tag.dataset.plugin = PLUGIN_ID
        tag.textContent = CSS
        document.head.appendChild(tag)
      }

      var scope = ctx.settingsScope.bind({ namespace: "command-quarantine", decode: function (v) { return v } })
      scope.load()

      ctx.slots.inject("settings.plugin.item", function* () {
        yield ctx.slots.register(
          { name: "settings.plugin.item", id: "command-quarantine", order: 30, label: "Command Quarantine" },
          function () { return React.createElement(SettingsCard, { scope: scope }) },
        )
      })
      ctx.slots.inject("conversation.input.left", function* () {
        yield ctx.slots.register(
          { name: "conversation.input.left", id: "command-quarantine-session", order: 10, label: "Command Quarantine session switch" },
          function (props) { return React.createElement(SessionSwitch, { sessionId: props.sessionId, scope: scope }) },
        )
      })
      ctx.slots.inject("conversation.view", function* () {
        yield ctx.slots.register(
          { name: "conversation.view", id: "cq-audit", order: 20, label: "CQ审计" },
          function (props) { return React.createElement(CqAuditView, { sessionId: props.sessionId }) },
        )
      })
    }

    exports.apply = apply
    exports.inject = ["slots", "settingsScope"]
    return module.exports
  }
})
