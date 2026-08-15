// ============================================================================
// 归档：动态插件时代的历史版本，仅供开发/临时参考；生产请使用 lib/ 固化版。
// ============================================================================
/**
 * DSH Command Quarantine — host half (Phase 1: deterministic review)
 * =====================================================================
 * A dynamic Cordis plugin that removes direct shell execution from the
 * session's main agent and routes every command through a quarantine zone:
 *
 *   main agent ──submit_command──▶ quarantine/{id}/  (script + meta, never runs)
 *        └─ request_review(id) ──▶ deterministic review (syntax + static rules)
 *                APPROVED ──▶ auto-execute (sandbox-confined) ──▶ result back
 *                RISKY    ──▶ user approval (approval service)  ──▶ execute / reject
 *                REJECTED ──▶ reason returned, agent resubmits
 *   audit/audit.jsonl + per-command stdout/stderr logs
 *
 * Portability: no Node built-ins are used (no require/process/Buffer/crypto).
 * SHA-256 is a pure-JS implementation. The interpreter table is probed at
 * runtime through the `subprocess` service, so the same code adapts to any
 * Windows host (pwsh/powershell, cmd, python, bash when installed). The
 * quarantine root is derived from the session workspace root — never
 * hard-coded.
 *
 * This file is the exact function body passed to `cordis_define` as code.host.
 * It returns a Cordis plugin.
 */

const QUARANTINE_DIR_NAME = 'quarantine'

/* Command-executing tool names that must never run directly. `run_code` is
 * intentionally excluded: nested pwsh dispatches inside it are still caught
 * by the pre-execute gate on their own names. */
const SHELL_TOOL_RE = /^(pwsh|powershell|bash|zsh|sh|cmd|shell|run_shell|terminal|exec)$/i

/* ---------------- pure JS SHA-256 (no crypto built-in available) ---------- */

function sha256hex(ascii) {
  const rr = (v, n) => ((v >>> n) | (v << (32 - n))) >>> 0
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]
  const bytes = new TextEncoder().encode(ascii)
  const l = bytes.length
  const padLen = (64 - ((l + 9) % 64)) % 64
  const total = l + 1 + padLen + 8
  const msg = new Uint8Array(total)
  msg.set(bytes)
  msg[l] = 0x80
  const bitLo = (l << 3) >>> 0
  msg[total - 4] = (bitLo >>> 24) & 0xff
  msg[total - 3] = (bitLo >>> 16) & 0xff
  msg[total - 2] = (bitLo >>> 8) & 0xff
  msg[total - 1] = bitLo & 0xff
  const w = new Uint32Array(64)
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) {
      const j = off + (i << 2)
      w[i] = ((msg[j] << 24) | (msg[j + 1] << 16) | (msg[j + 2] << 8) | msg[j + 3]) >>> 0
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15], y = w[i - 2]
      const s0 = rr(x, 7) ^ rr(x, 18) ^ (x >>> 3)
      const s1 = rr(y, 17) ^ rr(y, 19) ^ (y >>> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7
    for (let i = 0; i < 64; i++) {
      const S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)
      const ch = (e & f) ^ (~e & g)
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0
      const S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const t2 = (S0 + maj) >>> 0
      h = g; g = f; f = e; e = (d + t1) >>> 0
      d = c; c = b; b = a; a = (t1 + t2) >>> 0
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0
  }
  const hex = n => ('0000000' + n.toString(16)).slice(-8)
  return hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h5) + hex(h6) + hex(h7)
}

/* ---------------- static safety rule library ------------------------------ */

/* CRITICAL → REJECTED. WARNING → RISKY (user approval). INFO → noted only. */
const CRITICAL_RULES = [
  ['rmrf-root', /\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)\s+\//i, 'recursive forced delete of filesystem root'],
  ['mkfs', /\bmkfs\b/i, 'filesystem creation tool'],
  ['dd-dev', /\bdd\b[^;\n]*of=\/dev\//i, 'raw device write'],
  ['chmod777-root', /\bchmod\b[^;\n]*-R\s+777\s+\//i, 'world-writable permissions on filesystem root'],
  ['curl-sh', /\b(?:curl|wget)\b[^;\n]*\|\s*(?:sh|bash|pwsh|powershell|cmd)\b/i, 'download piped directly into a shell'],
  ['diskpart', /\b(?:diskpart|Clear-Disk|Initialize-Disk)\b/i, 'disk partition/wipe administration'],
  ['format', /\bformat\b[^;\n]*[a-z]:/i, 'drive format'],
  ['del-systemroot', /\b(?:Remove-Item|del|erase|rd|rmdir)\b[^;\n]*(?:\$env:SystemDrive|\$env:WINDIR|%SystemRoot%|%WINDIR%)/i, 'delete targeting the Windows directory'],
  ['del-sysdir', /\b(?:Remove-Item|del|erase|rd|rmdir|ren|rm)\b[^;\n]*(?:C:\\Windows\b|C:\\Program\s+Files\b|C:\\ProgramData\b|C:\\Users\b|C:\\System\s+Volume\s+Information\b)/i, 'delete targeting a Windows system directory'],
  ['del-driveroot', /\bRemove-Item\b[^;\n]*(?:-(?:Recurse|r)\b[^;\n]*[a-z]:\\|[a-z]:\\[^;\n]*-(?:Recurse|r)\b)/i, 'recursive delete at a drive root'],
  ['reg-hklm-write', /\b(?:New-ItemProperty|Set-ItemProperty|New-Item|Set-Item|reg\s+add)\b[^;\n]*HKLM/i, 'write to the HKLM registry hive'],
  ['download-exec', /\b(?:iex|Invoke-Expression)\b[^;\n]*(?:iwr|Invoke-WebRequest|curl|wget)/i, 'download-and-execute pattern'],
  ['shutdown', /\b(?:Stop-Computer|Restart-Computer)\b/i, 'system shutdown/restart'],
  ['forkbomb-cmd', /%0\|%0/, 'classic cmd fork bomb'],
  ['forkbomb-ps', /\bwhile\s*\(\s*(?:1|\$true)\s*\)\s*\{[^}]*Start-Process/i, 'PowerShell fork-bomb loop'],
  ['disable-defender', /\bSet-MpPreference\b[^;\n]*-DisableRealtimeMonitoring\s+\$true/i, 'disable Defender real-time monitoring'],
  ['stop-defender', /\bsc\.exe\b[^;\n]*\b(?:stop|delete)\b[^;\n]*WinDefend/i, 'stop the Defender service'],
  ['bcdedit', /\bbcdedit\b/i, 'boot configuration edit'],
  ['taskkill-tree', /\btaskkill\b[^;\n]*\/f[^;\n]*\/t/i, 'force-kill a process tree'],
]

const WARNING_RULES = [
  ['recurse-remove', /\bRemove-Item\b[^;\n]*-Recurse/i, 'recursive delete'],
  ['del-sq', /\bdel\b[^;\n]*\/s[^;\n]*\/q/i, 'quiet recursive delete (cmd)'],
  ['rd-sq', /\brd\b[^;\n]*\/s[^;\n]*\/q/i, 'quiet recursive rmdir (cmd)'],
  ['stop-process-force', /\bStop-Process\b[^;\n]*-Force/i, 'force-kill processes'],
  ['hidden-start', /\bStart-Process\b[^;\n]*(?:-WindowStyle\s+Hidden|-w\s+h)/i, 'launch a hidden process'],
  ['reg-hkcu-write', /\b(?:New-ItemProperty|Set-ItemProperty|reg\s+add)\b[^;\n]*HKCU/i, 'write to the HKCU registry hive'],
  ['env-write', /\b(?:Set-Item\s+Env:|setx\b|\[Environment\]::SetEnvironmentVariable)/i, 'persistent environment-variable change'],
  ['listener', /\b(?:Start-Listener|New-TcpListener|nc\s+-l|ncat\s+-l)\b/i, 'open a network listener'],
  ['persistence', /\b(?:Register-ScheduledTask|New-ScheduledTask|schtasks\s+\/create|New-Service)\b/i, 'schedule persistence'],
  ['credentials', /\b(?:ConvertTo-SecureString|Get-Credential|lsass|Read-Host\s+-AsSecureString)\b/i, 'credential handling'],
  ['disk-wipe', /\b(?:cipher\s+\/w|sdelete)\b/i, 'disk wipe tool'],
  ['shadow-copy', /\b(?:vssadmin|wmic\s+shadowcopy)\b/i, 'volume shadow-copy administration'],
]

const INFO_RULES = [
  ['unix-rm', /\brm\s+-/i, 'Unix-style rm flags are invalid in PowerShell'],
  ['unix-ls', /\bls\s+-/i, 'Unix-style ls flags are invalid in PowerShell'],
  ['unix-cp', /\bcp\s+-/i, 'Unix-style cp flags are invalid in PowerShell'],
  ['unix-sudo', /\bsudo\b/i, 'sudo does not exist on Windows'],
  ['unix-chmod', /\bchmod\b/i, 'chmod does not exist on Windows'],
  ['unix-which', /\bwhich\s+/i, 'use Get-Command instead of which'],
  ['unix-grep', /\bgrep\b/i, 'use Select-String instead of grep'],
]

const ABS_PATH_RE = /[A-Za-z]:[\\\/][^\s"'`;|<>]*/g
const UNC_RE = /\\\\[A-Za-z0-9._-]+\\[^\s"'`;|<>]*/g
const ENV_REF_RE = /\$env:[A-Za-z_][A-Za-z0-9_]*/gi
const PCTVAR_RE = /%[A-Za-z_][A-Za-z0-9_]*%/g
const DESTRUCTIVE_VERB_RE = /\b(Remove-Item|Remove-ItemProperty|del|erase|rd|rmdir|Clear-Content|Set-Content|Add-Content|Out-File|New-Item|mkdir|md|Move-Item|Copy-Item|Rename-Item|ren|format|Set-ItemProperty|New-ItemProperty|reg\s+add|Set-Item)\b/i

/* ---------------- interpreter table (runtime-probed, portable) ------------ */

function sq(s) {
  return "'" + String(s).replace(/'/g, "''") + "'"
}

const TOOL_TABLE = {
  powershell: {
    label: 'powershell', ext: '.ps1', candidates: ['pwsh', 'powershell'],
    syntax: 'parser',
    command: (exe, path) => 'Set-ExecutionPolicy -Scope Process Bypass -Force | Out-Null; & ' + sq(path),
    syntaxCommand: (exe, path) =>
      "$e=$null;$t=$null;[System.Management.Automation.Language.Parser]::ParseFile(" + sq(path) + ",[ref]$t,[ref]$e) | Out-Null;"
      + "if ($null -ne $e -and $e.Count -gt 0) { $e | ForEach-Object { 'ERR:' + $_.Extent.StartLineNumber + ':' + $_.Extent.StartColumnNumber + ' ' + $_.Message } } else { 'PARSER_OK' }",
  },
  cmd: {
    label: 'cmd', ext: '.bat', candidates: ['cmd'],
    syntax: 'heuristic',
    command: (exe, path) => '& ' + sq(exe) + ' /d /c call "' + String(path) + '"',
  },
  python: {
    label: 'python', ext: '.py', candidates: ['python', 'python3', 'py'],
    syntax: 'py_compile',
    command: (exe, path) => '& ' + sq(exe) + ' ' + sq(path),
    syntaxCommand: (exe, path) => '& ' + sq(exe) + ' -m py_compile ' + sq(path),
  },
  bash: {
    label: 'bash', ext: '.sh', candidates: ['bash', 'sh'],
    syntax: 'bash-n',
    command: (exe, path) => '& ' + sq(exe) + ' ' + sq(path),
    syntaxCommand: (exe, path) => '& ' + sq(exe) + ' -n ' + sq(path),
  },
}

/* ---------------- generic helpers ------------------------------------------ */

function errMsg(e) {
  if (e instanceof Error) return e.message
  if (e && typeof e === 'object' && typeof e.message === 'string') return e.message
  return String(e)
}

function normalizeWinPath(p) {
  const s = String(p).trim().replace(/\//g, '\\')
  const m = /^([a-z]:)\\/i.exec(s)
  const drive = m ? m[1] + '\\' : ''
  const rest = drive ? s.slice(3) : s
  const stack = []
  const parts = rest.split('\\')
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]
    if (part === '' || part === '.') continue
    if (part === '..') {
      if (stack.length > 0) stack.pop()
      continue
    }
    stack.push(part)
  }
  return drive + stack.join('\\')
}

function isInsideWorkspace(path, root) {
  const p = normalizeWinPath(path)
  if (!/^[a-z]:\\/i.test(p)) return true /* relative paths resolve inside the workspace */
  const r = normalizeWinPath(root).toLowerCase()
  const q = p.toLowerCase()
  return q === r || q.indexOf(r + '\\') === 0
}

function modeRank(m) {
  if (m === 'read-only') return 0
  if (m === 'workspace-write') return 1
  return 2 /* danger-full-access */
}

function effectiveMode(sessionMode, requestedMode) {
  return modeRank(requestedMode) < modeRank(sessionMode) ? requestedMode : sessionMode
}

let idCounter = 0
function genId() {
  idCounter = (idCounter + 1) % 1296
  return 'c' + Date.now().toString(36) + idCounter.toString(36) + Math.random().toString(36).slice(2, 6)
}

function tailOf(text, max) {
  const s = String(text || '')
  if (s.length <= max) return s
  return '[truncated — full text stored in the audit log]\n' + s.slice(-max)
}

function renderJson(_args, value) {
  return [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }]
}

/* Strip undefined fields so every execute return is lossless JSON. */
function cleanJson(v) {
  const s = JSON.stringify(v)
  return s === undefined ? null : JSON.parse(s)
}

/* ---------------- the plugin ------------------------------------------------- */

return {
  apply(ctx) {
    const fs = ctx.get('fs')
    const shell = ctx.get('shell')
    const subprocess = ctx.get('subprocess')
    const sandboxPolicy = ctx.get('sandboxPolicy')
    const approval = ctx.get('approval')
    const systemPrompt = ctx.get('systemPrompt')
    const llm = ctx.get('llm')
    const agents = ctx.get('agents')
    let cachedWorkspaceRoot
    if (fs === undefined || shell === undefined || subprocess === undefined || sandboxPolicy === undefined) {
      console.error('[cmdq] required services missing (fs/shell/subprocess/sandboxPolicy) — plugin inert')
      return
    }

    /* Seed the RPC workspace root from the initiating agent when available. */
    try {
      if (agents !== undefined) {
        const init = agents.currentInitiator()
        if (init !== undefined) sessionPolicy(init)
      }
    } catch (e) { /* optional seed */ }

    /* -- session policy + quarantine root helpers -- */
    function sessionPolicy(agent) {
      try {
        const pol = sandboxPolicy.resolve(agent && agent.session ? { session: agent.session } : {})
        if (pol && pol.workspaceRoot) cachedWorkspaceRoot = pol.workspaceRoot
        return pol
      } catch (e) {
        return sandboxPolicy.resolve()
      }
    }

    function qRoot(pol) {
      return normalizeWinPath(pol.workspaceRoot) + '\\' + QUARANTINE_DIR_NAME
    }

    /* -- file helpers over the fs service (no Node fs) -- */
    async function readTextFile(pol, path) {
      try {
        const target = await fs.resolve(path)
        return await fs.readText(target)
      } catch (e) {
        return undefined
      }
    }

    async function readJsonFile(pol, path) {
      const text = await readTextFile(pol, path)
      if (text === undefined || text === '') return undefined
      try {
        return JSON.parse(text)
      } catch (e) {
        return undefined
      }
    }

    async function writeTextFile(pol, path, content) {
      const target = await fs.resolve(path)
      return fs.writeText(target, content, undefined, undefined, pol)
    }

    async function writeJsonFile(pol, path, value) {
      return writeTextFile(pol, path, typeof value === 'string' ? value : JSON.stringify(value, null, 2))
    }

    /* -- directory creation: stat first, then a plugin-owned fixed mkdir -- */
    const madeDirs = new Set()
    async function ensureDir(pol, dirPath) {
      const key = normalizeWinPath(dirPath).toLowerCase()
      if (madeDirs.has(key)) return { ok: true }
      try {
        const target = await fs.resolve(dirPath)
        const info = await fs.stat(target)
        if (info !== undefined && info.type === 'directory') {
          madeDirs.add(key)
          return { ok: true }
        }
      } catch (e) { /* fall through to mkdir */ }
      const cmd = "New-Item -ItemType Directory -Force -Path " + sq(dirPath) + " | Out-Null"
      try {
        const spec = shell.resolve({ command: cmd, workdir: pol.workspaceRoot, timeoutMs: 30000, sandboxPolicy: pol })
        const r = await shell.run(spec)
        if (r.exitCode === 0) {
          madeDirs.add(key)
          return { ok: true }
        }
        return {
          ok: false,
          detail: 'mkdir exit=' + r.exitCode
            + ' stderr=' + String(r.stderr.text).slice(0, 300)
            + ' stdout=' + String(r.stdout.text).slice(0, 200)
            + (r.sandbox ? ' sandbox=' + JSON.stringify(r.sandbox) : ''),
        }
      } catch (e) {
        return { ok: false, detail: 'mkdir threw: ' + errMsg(e) }
      }
    }

    /* -- audit trail -- */
    async function auditAppend(pol, entry) {
      const root = qRoot(pol)
      const auditDir = root + '\\audit'
      const made = await ensureDir(pol, auditDir)
      if (!made.ok) return false
      const path = auditDir + '\\audit.jsonl'
      const before = await readTextFile(pol, path)
      const line = JSON.stringify(entry)
      await writeTextFile(pol, path, (before === undefined ? '' : before) + line + '\n')
      return true
    }

    async function indexUpdate(pol, id, patch) {
      const root = qRoot(pol)
      const path = root + '\\index.json'
      const idx = (await readJsonFile(pol, path)) || {}
      idx[id] = Object.assign({}, idx[id] || {}, patch, { updated_at: new Date().toISOString() })
      await writeJsonFile(pol, path, idx)
    }

    /* -- plugin configuration (settings entry; extensible) -- */
    const CONFIG_DEFAULTS = {
      version: 2,
      reviewScope: 'global', /* 'global' | 'per-session' | 'off' */
      reviewedSessions: [], /* session ids reviewed under 'per-session' */
      llmReview: true,
      reviewerMode: 'follow-session',
      reviewerProvider: '',
      reviewerModel: '',
      blockSubagents: true,
      interceptTools: true, /* master switch for command-tool interception */
      toolDenyList: [], /* user-selected intercepted tool names; empty = auto candidates */
    }

    function configDefaults() {
      return {
        version: 2,
        reviewScope: 'global',
        reviewedSessions: [],
        llmReview: true,
        reviewerMode: 'follow-session',
        reviewerProvider: '',
        reviewerModel: '',
        blockSubagents: true,
        interceptTools: true,
        toolDenyList: [],
      }
    }
    let liveConfig = configDefaults()

    async function readConfig(pol) {
      for (const root of candidateRoots()) {
        const p = polForRoot(root)
        try {
          const raw = await readJsonFile(p, root + '\\quarantine\\config.json')
          if (raw !== undefined && raw !== null && typeof raw === 'object') {
            const out = configDefaults()
            for (const k in CONFIG_DEFAULTS) {
              if (!Object.prototype.hasOwnProperty.call(CONFIG_DEFAULTS, k)) continue
              if (k === 'reviewedSessions' || k === 'toolDenyList') {
                out[k] = Array.isArray(raw[k]) ? raw[k].slice() : out[k]
              } else {
                out[k] = raw[k] !== undefined ? raw[k] : out[k]
              }
            }
            if (raw.mainSessionId !== undefined) out.mainSessionId = raw.mainSessionId
            liveConfig = out
            return out
          }
        } catch (e) { /* try the next candidate root */ }
      }
      liveConfig = configDefaults()
      return liveConfig
    }

    async function writeConfig(pol, patch) {
      const cur = await readConfig(pol)
      const next = Object.assign({}, cur, patch)
      const roots = candidateRoots()
      let targetRoot = roots.length > 0 ? roots[0] : undefined
      for (const root of roots) {
        const p = polForRoot(root)
        const existing = await readJsonFile(p, root + '\\quarantine\\config.json')
        if (existing !== undefined) {
          targetRoot = root
          break
        }
      }
      if (targetRoot === undefined) {
        try {
          const p0 = sandboxPolicy.resolve()
          if (p0 && p0.workspaceRoot) targetRoot = p0.workspaceRoot
        } catch (e) { /* keep undefined */ }
      }
      if (targetRoot === undefined) return next
      const p = polForRoot(targetRoot)
      const root = targetRoot + '\\quarantine'
      await ensureDir(p, root)
      await writeJsonFile(p, root + '\\config.json', next)
      liveConfig = next
      return next
    }

    /* -- interpreter probing (portable across Windows hosts) -- */
    async function probeTool(tool) {
      const t = TOOL_TABLE[tool]
      if (t === undefined) return undefined
      if (t.exe !== undefined) return t.exe === null ? undefined : t
      for (let i = 0; i < t.candidates.length; i++) {
        const candidate = t.candidates[i]
        try {
          const exe = await subprocess.resolveExecutable(candidate)
          if (exe) {
            t.exe = exe
            return t
          }
        } catch (e) { /* candidate not installed — try next */ }
      }
      t.exe = null
      return undefined
    }

    /* -- syntax checks -- */
    async function pwshSyntaxCheck(pol, scriptPath) {
      try {
        const cmd = TOOL_TABLE.powershell.syntaxCommand(undefined, scriptPath)
        const spec = shell.resolve({ command: cmd, workdir: pol.workspaceRoot, timeoutMs: 60000, sandboxPolicy: pol })
        const r = await shell.run(spec)
        const out = r.stdout.text
        if (r.exitCode !== 0 && out.indexOf('PARSER_OK') === -1) {
          return { status: 'FAIL', detail: (out || r.stderr.text).trim().slice(0, 2000) }
        }
        if (out.indexOf('PARSER_OK') !== -1) return { status: 'PASS', detail: 'PowerShell parser: no syntax errors' }
        return { status: 'FAIL', detail: (out || r.stderr.text).trim().slice(0, 2000) }
      } catch (e) {
        return { status: 'UNKNOWN', detail: 'parser unavailable: ' + errMsg(e) }
      }
    }

    async function runnerSyntaxCheck(pol, info, scriptPath) {
      try {
        const cmd = info.syntaxCommand(info.exe, scriptPath)
        const spec = shell.resolve({ command: cmd, workdir: pol.workspaceRoot, timeoutMs: 60000, sandboxPolicy: pol })
        const r = await shell.run(spec)
        if (r.exitCode === 0) return { status: 'PASS', detail: info.label + ' syntax check passed' }
        if (r.sandbox && r.sandbox.denied) return { status: 'UNKNOWN', detail: 'sandbox denied the syntax check write; cannot verify' }
        return { status: 'FAIL', detail: (r.stderr.text || r.stdout.text || '').trim().slice(0, 2000) }
      } catch (e) {
        return { status: 'UNKNOWN', detail: 'syntax checker unavailable: ' + errMsg(e) }
      }
    }

    function cmdHeuristicCheck(script) {
      if (script.trim() === '') return { status: 'FAIL', detail: 'script is empty' }
      const problems = []
      const lines = script.split(/\r?\n/)
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        let inQuote = false
        let depth = 0
        for (let j = 0; j < line.length; j++) {
          const ch = line.charAt(j)
          if (ch === '^') { j++; continue }
          if (ch === '"') inQuote = !inQuote
          else if (!inQuote && ch === '(') depth++
          else if (!inQuote && ch === ')') {
            depth--
            if (depth < 0) {
              problems.push('line ' + (i + 1) + ": unbalanced ')'")
              depth = 0
            }
          }
        }
        if (inQuote) problems.push('line ' + (i + 1) + ': unclosed quote')
        if (depth !== 0) problems.push('line ' + (i + 1) + ': unbalanced parentheses')
      }
      if (problems.length > 0) return { status: 'FAIL', detail: problems.slice(0, 10).join('; ') }
      return { status: 'PASS', detail: 'heuristic bracket/quote balance OK (cmd has no static checker)' }
    }

    async function runSyntaxCheck(pol, info, script, scriptPath) {
      if (info.syntax === 'parser') return pwshSyntaxCheck(pol, scriptPath)
      if (info.syntax === 'py_compile' || info.syntax === 'bash-n') return runnerSyntaxCheck(pol, info, scriptPath)
      return cmdHeuristicCheck(script)
    }

    /* -- path extraction for workspace-boundary isolation -- */
    function collectOutsidePaths(script, workspaceRoot) {
      const warnings = []
      const infos = []
      const seen = new Set()
      function note(kind, raw) {
        let p = String(raw).replace(/[*.,;)'"]+$/, '')
        if (seen.has(p.toLowerCase())) return
        seen.add(p.toLowerCase())
        const outside = !isInsideWorkspace(p, workspaceRoot)
        if (!outside) return
        if (DESTRUCTIVE_VERB_RE.test(script)) warnings.push('outside-workspace ' + kind + ' path "' + p + '" combined with a destructive verb')
        else infos.push('reads outside-workspace ' + kind + ' path "' + p + '"')
      }
      let m
      ABS_PATH_RE.lastIndex = 0
      while ((m = ABS_PATH_RE.exec(script)) !== null) note('absolute', m[0])
      UNC_RE.lastIndex = 0
      while ((m = UNC_RE.exec(script)) !== null) note('UNC', m[0])
      ENV_REF_RE.lastIndex = 0
      while ((m = ENV_REF_RE.exec(script)) !== null) {
        const ref = m[0]
        if (DESTRUCTIVE_VERB_RE.test(script)) warnings.push('references environment variable ' + ref + ' with a destructive verb')
        else infos.push('references environment variable ' + ref)
      }
      PCTVAR_RE.lastIndex = 0
      while ((m = PCTVAR_RE.exec(script)) !== null) {
        const ref = m[0]
        if (DESTRUCTIVE_VERB_RE.test(script)) warnings.push('references environment variable ' + ref + ' with a destructive verb')
        else infos.push('references environment variable ' + ref)
      }
      return { warnings, infos }
    }

    /* -- deterministic review -- */
    async function runReview(pol, info, meta, script, scriptPath) {
      const checks = []
      const syntax = await runSyntaxCheck(pol, info, script, scriptPath)
      checks.push({ name: 'syntax', status: syntax.status, detail: syntax.detail })

      const crits = []
      const warns = []
      const infos = []
      for (let i = 0; i < CRITICAL_RULES.length; i++) {
        const rule = CRITICAL_RULES[i]
        if (rule[1].test(script)) crits.push(rule[0] + ': ' + rule[2])
      }
      for (let i = 0; i < WARNING_RULES.length; i++) {
        const rule = WARNING_RULES[i]
        if (rule[1].test(script)) warns.push(rule[0] + ': ' + rule[2])
      }
      for (let i = 0; i < INFO_RULES.length; i++) {
        const rule = INFO_RULES[i]
        if (rule[1].test(script)) infos.push(rule[0] + ': ' + rule[2] + ' (verify before running)')
      }
      const paths = collectOutsidePaths(script, pol.workspaceRoot)
      warns.push.apply(warns, paths.warnings)
      infos.push.apply(infos, paths.infos)

      if (crits.length > 0) checks.push({ name: 'static', status: 'FAIL', detail: crits.slice(0, 6).join(' | ') })
      else if (warns.length > 0) checks.push({ name: 'static', status: 'WARN', detail: warns.slice(0, 6).join(' | ') })
      else checks.push({ name: 'static', status: 'PASS', detail: 'no dangerous pattern matched' })

      let verdict
      let riskLevel
      if (syntax.status === 'FAIL' || crits.length > 0) {
        verdict = 'REJECTED'
        riskLevel = crits.length > 0 ? 'CRITICAL' : 'HIGH'
      } else if (warns.length > 0 || syntax.status === 'UNKNOWN') {
        verdict = 'RISKY'
        riskLevel = warns.length >= 3 ? 'HIGH' : 'MEDIUM'
      } else {
        verdict = 'APPROVED'
        riskLevel = 'LOW'
      }

      const reasonParts = []
      if (syntax.status === 'FAIL') reasonParts.push('syntax: ' + syntax.detail)
      if (syntax.status === 'UNKNOWN') reasonParts.push('syntax could not be verified (fail closed): ' + syntax.detail)
      reasonParts.push.apply(reasonParts, crits)
      reasonParts.push.apply(reasonParts, warns)
      reasonParts.push.apply(reasonParts, infos)
      if (reasonParts.length === 0) reasonParts.push('syntax OK and no dangerous pattern matched')

      return {
        id: meta.id,
        reviewed_by: 'deterministic-reviewer',
        verdict,
        risk_level: riskLevel,
        tool: meta.tool,
        syntax_check: syntax.status,
        static_check: crits.length > 0 ? 'FAIL' : (warns.length > 0 ? 'WARN' : 'PASS'),
        checks,
        reason: reasonParts.slice(0, 10).join('\n'),
      }
    }

    /* -- user approval for RISKY -- */
    async function askUser(exec, meta, review, script) {
      if (approval === undefined) return 'unavailable'
      try {
        return await approval.request({
          agent: exec && exec.agent,
          toolName: 'request_review',
          callId: exec && exec.callId,
          reason: '[Command Quarantine] RISKY command needs approval\n'
            + 'command_id: ' + meta.id + '\n'
            + 'tool: ' + meta.tool + '\n'
            + 'intent: ' + String(meta.intent || '') + '\n'
            + 'risk_level: ' + review.risk_level + '\n'
            + 'reason: ' + review.reason + '\n'
            + 'script:\n' + tailOf(script, 1500),
          signal: exec && exec.signal,
        })
      } catch (e) {
        return 'unavailable'
      }
    }

    /* -- Phase 2: independent LLM reviewer child agent (no shell, 3 tools) -- */

    function foldAssistantText(events) {
      let messageBlocks
      let partial = ''
      if (!Array.isArray(events)) return undefined
      for (let i = 0; i < events.length; i++) {
        const ev = events[i]
        if (ev === null || typeof ev !== 'object') continue
        if (ev.type === 'assistant/message' && ev.data !== null && typeof ev.data === 'object'
          && ev.data.message !== null && typeof ev.data.message === 'object'
          && Array.isArray(ev.data.message.content) && ev.data.message.content.length > 0) {
          messageBlocks = ev.data.message.content
        } else if (ev.type === 'assistant/chunk' && ev.data !== null && typeof ev.data === 'object'
          && ev.data.chunk !== null && typeof ev.data.chunk === 'object' && ev.data.chunk.type === 'text-delta') {
          partial += String(ev.data.chunk.text)
        }
      }
      const blocks = messageBlocks !== undefined ? messageBlocks : (partial.length > 0 ? [{ type: 'text', text: partial }] : [])
      let text = ''
      for (let i = 0; i < blocks.length; i++) {
        const b = blocks[i]
        if (b !== null && typeof b === 'object' && b.type === 'text') text += String(b.text)
        else if (b !== null && typeof b === 'object' && b.type === 'tool_use') text += '\n[tool call: ' + String(b.name) + ']'
      }
      return text.trim()
    }

    function buildReviewerTools(pol, parentAgent, dir, meta) {
      const readQ = harness.defineTool({
        name: 'read_quarantine_file',
        description: 'Read one file of the quarantined command under review (meta.json, the script, review.json, audit.json, stdout.log, stderr.log). Nothing else can be read.',
        parameters: {
          type: 'object',
          properties: {
            command_id: { type: 'string', description: 'The command_id under review.' },
            filename: { type: 'string', description: 'One of: meta.json, script.ps1, script.bat, script.py, script.sh, review.json, audit.json, stdout.log, stderr.log' },
          },
          additionalProperties: true,
          required: ['command_id', 'filename'],
        },
        output: { schema: { type: 'json' }, render: renderJson },
        timeoutMs: 30000,
        execute: async (args, _exec) => {
          const id = String(args.command_id || '').toLowerCase()
          if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) return { error: 'invalid command_id' }
          if (id !== meta.id) return { error: 'you may only read files of the command under review (' + meta.id + ')' }
          const fn = String(args.filename || '')
          if (!/^(meta\.json|script\.(ps1|bat|py|sh)|review\.json|audit\.json|stdout\.log|stderr\.log)$/.test(fn)) {
            return { error: 'filename not allowed (only this command\'s quarantine files)' }
          }
          const text = await readTextFile(pol, dir + '\\' + fn)
          if (text === undefined) return { error: 'file not found' }
          return { command_id: id, filename: fn, content: text.slice(0, 50000) }
        },
      })

      const writeRev = harness.defineTool({
        name: 'write_review',
        description: 'Write your review verdict for the command under review. Only its review.json and status change — no other file can be written.',
        parameters: {
          type: 'object',
          properties: {
            command_id: { type: 'string', description: 'The command_id under review.' },
            verdict: { type: 'string', enum: ['APPROVED', 'RISKY', 'REJECTED'], description: 'APPROVED = safe, execute it; RISKY = the human user must approve; REJECTED = dangerous or broken.' },
            reason: { type: 'string', description: 'Concise concrete findings and why this verdict.' },
          },
          additionalProperties: true,
          required: ['command_id', 'verdict', 'reason'],
        },
        output: { schema: { type: 'json' }, render: renderJson },
        timeoutMs: 30000,
        execute: async (args, exec) => {
          const id = String(args.command_id || '').toLowerCase()
          if (id !== meta.id) return { error: 'you may only review the command under review (' + meta.id + ')' }
          const fresh = await readJsonFile(pol, dir + '\\meta.json')
          if (fresh === undefined) return { error: 'command not found' }
          if (fresh.status === 'EXECUTED') return { error: 'command already executed; the review is final' }
          const verdict = String(args.verdict || '')
          if (verdict !== 'APPROVED' && verdict !== 'RISKY' && verdict !== 'REJECTED') return { error: 'verdict must be APPROVED, RISKY or REJECTED' }
          const review = {
            id,
            reviewed_by: 'llm-reviewer',
            verdict,
            risk_level: verdict === 'APPROVED' ? 'LOW' : (verdict === 'RISKY' ? 'MEDIUM' : 'HIGH'),
            tool: fresh.tool,
            syntax_check: 'n/a (llm review)',
            static_check: 'n/a (llm review)',
            reason: String(args.reason || '').slice(0, 4000),
            reviewed_at: new Date().toISOString(),
          }
          await writeJsonFile(pol, dir + '\\review.json', review)
          fresh.status = verdict === 'APPROVED' ? 'APPROVED' : (verdict === 'RISKY' ? 'USER_REVIEW' : 'REJECTED')
          fresh.updated_at = new Date().toISOString()
          await writeJsonFile(pol, dir + '\\meta.json', fresh)
          await indexUpdate(pol, id, { status: fresh.status, verdict: fresh.status === 'USER_REVIEW' ? 'RISKY' : verdict })
          const childId = exec && exec.agent && exec.agent.session ? String(exec.agent.session.id) : 'unknown'
          await auditAppend(pol, { event: 'REVIEW', id, ts: review.reviewed_at, actor: 'llm-reviewer', child_session: childId, verdict, risk_level: review.risk_level, reason: review.reason.slice(0, 500) })
          return cleanJson({ ok: true, command_id: id, verdict, status: fresh.status, next: verdict === 'APPROVED' ? 'call execute_approved(command_id) to run it' : 'do NOT execute; summarize your verdict in your reply' })
        },
      })

      const execAppr = harness.defineTool({
        name: 'execute_approved',
        description: 'Execute the command under review. Only works when its status is APPROVED. The script text is read from the quarantine zone — never from your message.',
        parameters: {
          type: 'object',
          properties: {
            command_id: { type: 'string', description: 'The command_id to execute.' },
          },
          additionalProperties: true,
          required: ['command_id'],
        },
        output: { schema: { type: 'json' }, render: renderJson },
        timeoutMs: 320000,
        execute: async (args, _exec) => {
          const id = String(args.command_id || '').toLowerCase()
          if (id !== meta.id) return { error: 'you may only execute the command under review (' + meta.id + ')' }
          const fresh = await readJsonFile(pol, dir + '\\meta.json')
          if (fresh === undefined) return { error: 'command not found' }
          if (fresh.status === 'EXECUTED') {
            const audit = await readJsonFile(pol, dir + '\\audit.json')
            return cleanJson({ already_executed: true, exit_code: audit ? audit.exit_code : null, executed_at: audit ? audit.executed_at : null })
          }
          if (fresh.status !== 'APPROVED') return { error: 'command status is ' + fresh.status + ' — write_review with verdict APPROVED first' }
          const script = await readTextFile(pol, dir + '\\' + fresh.script_file)
          if (script === undefined) return { error: 'script file missing' }
          if (sha256hex(script) !== fresh.script_sha256) return { error: 'script hash mismatch — tampering detected; report this' }
          const info = await probeTool(fresh.tool)
          if (info === undefined) return { error: 'interpreter for "' + fresh.tool + '" is not installed on this host' }
          const summary = await executeApproved(pol, dir, fresh, parentAgent, info)
          return cleanJson({ executed: true, exit_code: summary.exit_code, sandbox: summary.sandbox, stdout_tail: summary.stdout_tail, stderr_tail: summary.stderr_tail })
        },
      })

      return [readQ, writeRev, execAppr]
    }

    async function spawnReviewerChild(pol, parentAgent, dir, meta, script, signal, cfg) {
      const agents = ctx.get('agents')
      if (agents === undefined) return { ok: false, error: 'agents service unavailable' }
      const scriptFileName = meta.script_file
      const prompt = 'You are a strict, independent command reviewer inside a command quarantine zone.\n'
        + 'You have exactly three tools and NOTHING else: read_quarantine_file, write_review, execute_approved.\n'
        + 'You cannot run shell commands, cannot write files, cannot browse the network, and must not delegate to anyone.\n\n'
        + 'Review this submitted command:\n'
        + '- command_id: ' + meta.id + '\n'
        + '- tool/interpreter: ' + meta.tool + '\n'
        + '- intent: ' + String(meta.intent || '') + '\n'
        + '- working_directory: ' + String(meta.working_directory || '') + '\n'
        + '- timeout_seconds: ' + meta.timeout_seconds + '\n'
        + '- sandbox_mode: ' + meta.sandbox_mode + '\n\n'
        + 'Steps:\n'
        + '1. read_quarantine_file(command_id, "meta.json") and read_quarantine_file(command_id, "' + scriptFileName + '") to read the exact script.\n'
        + '2. Analyze the script for: syntax errors, dangerous operations (destructive deletes, system paths, registry writes, download-and-execute, persistence, credential theft), and Unix-style commands that are invalid in the declared interpreter.\n'
        + '3. Verdict: APPROVED (safe — approve and execute), RISKY (the human user must approve), REJECTED (dangerous or broken — do not execute).\n'
        + '4. write_review(command_id, verdict, reason) with concise concrete findings.\n'
        + '5. If APPROVED: call execute_approved(command_id) and include its result in your reply.\n'
        + '   If RISKY or REJECTED: do NOT execute.\n'
        + 'End your reply with a line starting "VERDICT: " followed by APPROVED, RISKY or REJECTED, then your reason and any execution outcome.'

      const childDepth = ((parentAgent && parentAgent.session && parentAgent.session.header
        && parentAgent.session.header.delegationDepth) || 0) + 1
      const childId = 'rv-' + genId()
      const reviewerTools = buildReviewerTools(pol, parentAgent, dir, meta)

      const setup = (childCtx) => {
        try {
          const ap = childCtx.get('agentPresets')
          if (ap !== undefined && parentAgent !== undefined && parentAgent.ctx !== undefined) ap.composeFrom(childCtx, parentAgent.ctx)
        } catch (e) {
          console.error('[cmdq] reviewer preset join failed: ' + errMsg(e))
        }
        try {
          const globals = childCtx.tools.schemas().map(s => s.name).filter(n => !/^run_code/.test(n))
          if (globals.length > 0) childCtx.tools.restrict({ deny: globals })
        } catch (e) {
          console.error('[cmdq] reviewer global-tool restrict failed: ' + errMsg(e))
        }
        try {
          childCtx.on('tools/pre-execute', (cex, next) => {
            if (cex !== null && typeof cex === 'object' && typeof cex.name === 'string' && SHELL_TOOL_RE.test(cex.name)) {
              return { kind: 'deny', reason: 'reviewer agents may not run shell commands' }
            }
            return next()
          })
        } catch (e) {
          console.error('[cmdq] reviewer pre-execute gate failed: ' + errMsg(e))
        }
        for (const t of reviewerTools) {
          try {
            childCtx.tools.register(t)
          } catch (e) {
            console.error('[cmdq] reviewer tool registration failed: ' + errMsg(e))
          }
        }
      }

      const agentOptions = {}
      if (cfg && cfg.reviewerMode === 'custom' && cfg.reviewerProvider) {
        agentOptions.provider = String(cfg.reviewerProvider)
        if (cfg.reviewerModel) agentOptions.model = String(cfg.reviewerModel)
      } else if (parentAgent && parentAgent.options) {
        if (parentAgent.options.provider !== undefined) agentOptions.provider = parentAgent.options.provider
        if (parentAgent.options.model !== undefined) agentOptions.model = parentAgent.options.model
        if (parentAgent.options.maxTokens !== undefined) agentOptions.maxTokens = parentAgent.options.maxTokens
      }
      agentOptions.subagentDepth = childDepth

      const childMeta = {}
      const hdr = parentAgent && parentAgent.session ? parentAgent.session.header : undefined
      if (hdr) {
        if (hdr.cwd !== undefined) childMeta.cwd = hdr.cwd
        childMeta.parentSession = hdr.id
      }
      try {
        const ap2 = ctx.get('agentPresets')
        if (ap2 !== undefined && parentAgent && parentAgent.ctx !== undefined) {
          const presetName = ap2.composedPreset(parentAgent.ctx)
          if (presetName !== undefined) childMeta.agentPreset = presetName
        }
      } catch (e) { /* preset metadata optional */ }
      childMeta.origin = 'subagent'
      childMeta.delegationDepth = childDepth

      const handle = await agents.create({
        sessionId: childId,
        meta: childMeta,
        agentOptions,
        signal,
        setup,
      })
      const child = handle.agent
      child.followup({
        id: 'rqmsg-' + genId(),
        role: 'user',
        content: [{ type: 'text', text: prompt }],
        source: { kind: 'user' },
      })
      await child.whenIdle()
      const events = child.session ? child.session.events : []
      const report = foldAssistantText(events)
      await handle.dispose()
      return { ok: true, report, child_session: childId }
    }

    /* -- executor: only command_id-derived paths, never agent text -- */
    async function executeApproved(pol, dir, meta, agent, info) {
      const scriptPath = dir + '\\' + meta.script_file
      const effMode = effectiveMode(pol.mode, meta.sandbox_mode || 'read-only')
      const command = info.command(info.exe, scriptPath)
      const started = Date.now()
      const spec = shell.resolve({
        command,
        workdir: meta.working_directory || pol.workspaceRoot,
        timeoutMs: meta.timeout_seconds * 1000,
        stdoutMaxBytes: 200000,
        sandboxPolicy: { mode: effMode, workspaceRoot: pol.workspaceRoot, sessionId: pol.sessionId },
      })
      const r = await shell.run(spec)
      const duration = Date.now() - started

      const stdoutFile = dir + '\\stdout.log'
      const stderrFile = dir + '\\stderr.log'
      await writeTextFile(pol, stdoutFile, r.stdout.text)
      await writeTextFile(pol, stderrFile, r.stderr.text)

      const audit = {
        id: meta.id,
        executed_at: new Date().toISOString(),
        exit_code: r.exitCode,
        timed_out: r.timedOut,
        aborted: r.aborted,
        duration_ms: duration,
        sandbox: {
          mode: effMode,
          denied: !!(r.sandbox && r.sandbox.denied),
          enforcement: r.sandbox ? r.sandbox.enforcement : undefined,
        },
        executed_by: 'quarantine-executor',
        command_hash: meta.script_sha256,
        stdout_file: 'stdout.log',
        stderr_file: 'stderr.log',
      }
      await writeJsonFile(pol, dir + '\\audit.json', audit)
      await auditAppend(pol, { event: 'EXECUTE', id: meta.id, ts: audit.executed_at, actor: 'quarantine-executor', exit_code: r.exitCode, duration_ms: duration, sandbox: audit.sandbox })
      await auditAppend(pol, { event: 'COMPLETE', id: meta.id, ts: new Date().toISOString(), actor: 'quarantine-executor', exit_code: r.exitCode })

      meta.status = 'EXECUTED'
      meta.executed_at = audit.executed_at
      await writeJsonFile(pol, dir + '\\meta.json', meta)
      await indexUpdate(pol, meta.id, { status: 'EXECUTED', exit_code: r.exitCode })

      return cleanJson({
        exit_code: r.exitCode,
        timed_out: r.timedOut,
        aborted: r.aborted,
        duration_ms: duration,
        sandbox: audit.sandbox,
        stdout_tail: tailOf(r.stdout.text, 4000),
        stderr_tail: tailOf(r.stderr.text, 4000),
        files: { audit: dir + '\\audit.json', stdout: stdoutFile, stderr: stderrFile },
      })
    }

    async function updateMetaStatus(pol, dir, meta, status) {
      meta.status = status
      meta.updated_at = new Date().toISOString()
      await writeJsonFile(pol, dir + '\\meta.json', meta)
    }

    /* ---------------- model tools ---------------- */

    const submitTool = harness.defineTool({
      name: 'submit_command',
      description: 'Write a command into the quarantine zone for review. It NEVER executes anything. Direct shell tools are disabled in this session, so this is the only way to run commands. Returns a command_id to pass to request_review.',
      parameters: {
        type: 'object',
        properties: {
          script: { type: 'string', description: 'The exact script/command text. It is only written to the quarantine zone, not executed here.' },
          tool: { type: 'string', enum: ['powershell', 'cmd', 'python', 'bash'], description: 'Interpreter for the script. Runtime-probed on this host; unavailable ones are rejected.' },
          intent: { type: 'string', description: 'Why this command is needed — reviewers and audit readers see this.' },
          working_directory: { type: 'string', description: 'Optional working directory; must stay inside the session workspace. Defaults to the workspace root.' },
          timeout_seconds: { type: 'integer', description: 'Execution timeout 1-300s. Default 30.' },
          sandbox_mode: { type: 'string', enum: ['read-only', 'workspace-write'], description: 'Requested file sandbox mode. Can only lower the session policy, never raise it. Default read-only.' },
        },
        additionalProperties: true,
        required: ['script', 'tool', 'intent'],
      },
      output: { schema: { type: 'json' }, render: renderJson },
      timeoutMs: 30000,
      execute: async (args, exec) => {
        try {
          const pol = sessionPolicy(exec && exec.agent)
          if (!pol || !pol.workspaceRoot) return { error: 'no workspace root available from the sandbox policy' }
          const tool = String(args.tool || '').toLowerCase()
          const info = await probeTool(tool)
          if (info === undefined) {
            return { error: 'tool "' + tool + '" is not in the allowlist or its interpreter is not installed on this host. Available: powershell (.ps1), cmd (.bat)' + ' (python/bash when installed).' }
          }
          const script = String(args.script || '')
          if (script.trim() === '') return { error: 'script must not be empty' }
          if (script.length > 100000) return { error: 'script is too long (>100000 chars)' }

          let wd = args.working_directory !== undefined && args.working_directory !== null && String(args.working_directory).trim() !== ''
            ? String(args.working_directory)
            : pol.workspaceRoot
          wd = normalizeWinPath(wd)
          if (!/^[a-z]:\\/i.test(wd)) wd = normalizeWinPath(pol.workspaceRoot) + '\\' + wd
          if (!isInsideWorkspace(wd, pol.workspaceRoot)) {
            return { error: 'working_directory must stay inside the session workspace (' + pol.workspaceRoot + ')' }
          }

          let timeout = 30
          if (args.timeout_seconds !== undefined && args.timeout_seconds !== null) {
            timeout = Math.floor(Number(args.timeout_seconds))
            if (!(timeout >= 1)) timeout = 30
            if (timeout > 300) timeout = 300
          }
          let mode = 'read-only'
          if (args.sandbox_mode === 'workspace-write') mode = 'workspace-write'

          const id = genId()
          const dir = qRoot(pol) + '\\' + id
          const made = await ensureDir(pol, dir)
          if (!made.ok) {
            return { error: 'could not create the quarantine directory: ' + (made.detail || 'unknown reason') + ' (mode=' + pol.mode + ', root=' + pol.workspaceRoot + ')' }
          }
          const scriptFile = 'script' + info.ext
          const hash = sha256hex(script)
          const meta = {
            id,
            status: 'PENDING',
            tool,
            submitted_by: 'main-agent',
            intent: String(args.intent || '').slice(0, 500),
            created_at: new Date().toISOString(),
            script_sha256: hash,
            script_file: scriptFile,
            working_directory: wd,
            timeout_seconds: timeout,
            sandbox_mode: mode,
            tags: [],
          }
          await writeTextFile(pol, dir + '\\' + scriptFile, script)
          await writeJsonFile(pol, dir + '\\meta.json', meta)
          await auditAppend(pol, { event: 'SUBMIT', id, ts: meta.created_at, actor: 'main-agent', tool, intent: meta.intent, sha256: hash })
          await indexUpdate(pol, id, { status: 'PENDING', tool, intent: meta.intent, submitted_at: meta.created_at })
          if (exec && exec.agent && exec.agent.session) {
            try {
              await writeConfig(pol, { mainSessionId: String(exec.agent.session.id) })
            } catch (e) { /* config write is best-effort */ }
          }
          console.log('[cmdq] SUBMIT ' + id + ' tool=' + tool + ' intent=' + meta.intent)
          return cleanJson({
            command_id: id,
            status: 'PENDING',
            tool,
            script_file: scriptFile,
            quarantine_dir: dir,
            sha256: hash,
            next_step: 'call request_review(command_id) to run the syntax + safety review',
          }
        } catch (e) {
          return { error: 'submit failed: ' + errMsg(e) }
        }
      },
    })

    const reviewTool = harness.defineTool({
      name: 'request_review',
      description: 'Review a submitted command_id: deterministic pre-checks (syntax + static safety rules) first, then an independent LLM reviewer sub-agent (no shell tools) issues the final verdict. APPROVED executes automatically with output returned; RISKY asks the user; REJECTED returns the reason.',
      parameters: {
        type: 'object',
        properties: {
          command_id: { type: 'string', description: 'The command_id returned by submit_command.' },
        },
        additionalProperties: true,
        required: ['command_id'],
      },
      output: { schema: { type: 'json' }, render: renderJson },
      timeoutMs: 330000,
      execute: async (args, exec) => {
        try {
          const id = String(args.command_id || '').toLowerCase()
          if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) return { error: 'invalid command_id format' }
          const pol = sessionPolicy(exec && exec.agent)
          const dir = qRoot(pol) + '\\' + id
          const meta = await readJsonFile(pol, dir + '\\meta.json')
          if (meta === undefined) return { error: 'no such command "' + id + '" in the quarantine zone' }

          if (meta.status === 'EXECUTED') {
            const audit = await readJsonFile(pol, dir + '\\audit.json')
            const review = await readJsonFile(pol, dir + '\\review.json')
            return cleanJson({
              command_id: id,
              status: 'EXECUTED',
              note: 'this command already ran; showing recorded outcome',
              review: review === undefined ? undefined : { verdict: review.verdict, risk_level: review.risk_level, reason: review.reason },
              execution: audit === undefined ? undefined : { exit_code: audit.exit_code, executed_at: audit.executed_at, duration_ms: audit.duration_ms, stdout_file: dir + '\\' + audit.stdout_file, stderr_file: dir + '\\' + audit.stderr_file },
            }
          }
          if (meta.status === 'REJECTED') {
            const review = await readJsonFile(pol, dir + '\\review.json')
            return cleanJson({ command_id: id, status: 'REJECTED', reason: review === undefined ? 'rejected earlier' : review.reason, next_step: 'fix the script and submit a new command' })
          }

          const script = await readTextFile(pol, dir + '\\' + meta.script_file)
          if (script === undefined) return { error: 'script file is missing from the quarantine dir' }
          const hash = sha256hex(script)
          if (hash !== meta.script_sha256) return { error: 'script hash mismatch — the file was tampered with or corrupted; submit a new command' }

          const info = await probeTool(meta.tool)
          if (info === undefined) return { error: 'the interpreter for tool "' + meta.tool + '" is not installed on this host; the command cannot be reviewed or executed' }

          await updateMetaStatus(pol, dir, meta, 'UNDER_REVIEW')
          await indexUpdate(pol, id, { status: 'UNDER_REVIEW' })

          const review = await runReview(pol, info, meta, script, dir + '\\' + meta.script_file)
          review.reviewed_at = new Date().toISOString()
          await writeJsonFile(pol, dir + '\\review.json', review)
          await auditAppend(pol, { event: 'REVIEW', id, ts: review.reviewed_at, actor: 'deterministic-reviewer', verdict: review.verdict, risk_level: review.risk_level, reason: review.reason.slice(0, 500) })
          console.log('[cmdq] REVIEW ' + id + ' verdict=' + review.verdict + ' risk=' + review.risk_level)

          if (review.verdict === 'REJECTED') {
            await updateMetaStatus(pol, dir, meta, 'REJECTED')
            await indexUpdate(pol, id, { status: 'REJECTED', verdict: 'REJECTED' })
            await auditAppend(pol, { event: 'REJECT', id, ts: new Date().toISOString(), actor: 'deterministic-reviewer', reason: review.reason.slice(0, 500) })
            return cleanJson({ command_id: id, status: 'REJECTED', verdict: 'REJECTED', risk_level: review.risk_level, checks: review.checks, reason: review.reason, next_step: 'fix the script and submit a new command' })
          }

          /* Phase 2: the independent LLM reviewer child decides the final verdict. */
          const cfg = await readConfig(pol)
          const llm = cfg.llmReview === false
            ? { ok: false, error: 'llm review disabled by plugin configuration' }
            : await spawnReviewerChild(pol, exec && exec.agent, dir, meta, script, exec && exec.signal, cfg)
          if (llm.ok) {
            const afterMeta = await readJsonFile(pol, dir + '\\meta.json')
            const afterReview = await readJsonFile(pol, dir + '\\review.json')
            const status = afterMeta ? afterMeta.status : 'UNKNOWN'
            if (status === 'EXECUTED') {
              const audit = await readJsonFile(pol, dir + '\\audit.json')
              const std = await readTextFile(pol, dir + '\\stdout.log')
              return cleanJson({
                command_id: id,
                status: 'EXECUTED',
                verdict: afterReview ? afterReview.verdict : 'APPROVED',
                reviewer: 'llm-reviewer',
                reviewer_report: llm.report,
                execution: {
                  exit_code: audit ? audit.exit_code : null,
                  duration_ms: audit ? audit.duration_ms : null,
                  sandbox: audit ? audit.sandbox : null,
                  stdout_tail: std === undefined ? '' : tailOf(std, 4000),
                },
              })
            }
            if (status === 'APPROVED') {
              const info = await probeTool(afterMeta.tool)
              if (info === undefined) return { error: 'interpreter for "' + afterMeta.tool + '" is not installed on this host' }
              const execution = await executeApproved(pol, dir, afterMeta, exec && exec.agent, info)
              await auditAppend(pol, { event: 'APPROVE', id, ts: new Date().toISOString(), actor: 'llm-reviewer' })
              return cleanJson({
                command_id: id,
                status: 'EXECUTED',
                verdict: 'APPROVED',
                reviewer: 'llm-reviewer',
                reviewer_report: llm.report,
                execution,
              })
            }
            if (status === 'USER_REVIEW') {
              const effectiveReview = (afterReview && afterReview.verdict) ? afterReview : review
              const outcome = await askUser(exec, afterMeta, effectiveReview, script)
              if (outcome === 'allowed-once') {
                effectiveReview.user_approval = { approved_by: 'user', approved_at: new Date().toISOString() }
                await writeJsonFile(pol, dir + '\\review.json', effectiveReview)
                await updateMetaStatus(pol, dir, afterMeta, 'APPROVED')
                await indexUpdate(pol, id, { status: 'APPROVED', verdict: 'RISKY-APPROVED' })
                await auditAppend(pol, { event: 'APPROVE', id, ts: new Date().toISOString(), actor: 'user' })
                const info = await probeTool(afterMeta.tool)
                if (info === undefined) return { error: 'interpreter for "' + afterMeta.tool + '" is not installed on this host' }
                const execution = await executeApproved(pol, dir, afterMeta, exec && exec.agent, info)
                return cleanJson({
                  command_id: id,
                  status: 'EXECUTED',
                  verdict: 'APPROVED',
                  reviewer: 'llm-reviewer',
                  reviewer_report: llm.report,
                  execution,
                })
              }
              if (outcome === 'cancelled') {
                return cleanJson({ command_id: id, status: 'USER_REVIEW', verdict: 'RISKY', reviewer: 'llm-reviewer', reviewer_report: llm.report, reason: afterReview ? afterReview.reason : review.reason, note: 'user approval was cancelled; the command stays in USER_REVIEW' })
              }
              await updateMetaStatus(pol, dir, afterMeta, 'REJECTED')
              await indexUpdate(pol, id, { status: 'REJECTED', verdict: 'RISKY-REJECTED' })
              await auditAppend(pol, { event: 'REJECT', id, ts: new Date().toISOString(), actor: outcome === 'rejected' ? 'user' : 'system', reason: 'risky command not approved' })
              return cleanJson({ command_id: id, status: 'REJECTED', verdict: 'RISKY', reviewer: 'llm-reviewer', reviewer_report: llm.report, reason: 'the risky command was not approved' + (outcome === 'unavailable' ? ' (no approval answerer available — fail closed)' : ' by the user') })
            }
            if (status === 'REJECTED') {
              return cleanJson({ command_id: id, status: 'REJECTED', verdict: 'REJECTED', reviewer: 'llm-reviewer', reviewer_report: llm.report, reason: afterReview ? afterReview.reason : 'rejected by the reviewer', next_step: 'fix the script and submit a new command' })
            }
            /* reviewer produced no valid state → deterministic fallback below */
          }

          if (review.verdict === 'RISKY') {
            await updateMetaStatus(pol, dir, meta, 'USER_REVIEW')
            await indexUpdate(pol, id, { status: 'USER_REVIEW', verdict: 'RISKY' })
            const outcome = await askUser(exec, meta, review, script)
            if (outcome === 'allowed-once') {
              review.user_approval = { approved_by: 'user', approved_at: new Date().toISOString() }
              await writeJsonFile(pol, dir + '\\review.json', review)
              await updateMetaStatus(pol, dir, meta, 'APPROVED')
              await indexUpdate(pol, id, { status: 'APPROVED', verdict: 'RISKY-APPROVED' })
              await auditAppend(pol, { event: 'APPROVE', id, ts: new Date().toISOString(), actor: 'user' })
            } else if (outcome === 'cancelled') {
              return cleanJson({ command_id: id, status: 'USER_REVIEW', verdict: 'RISKY', risk_level: review.risk_level, checks: review.checks, reason: review.reason, note: 'user approval was cancelled; the command stays in USER_REVIEW' })
            } else {
              await updateMetaStatus(pol, dir, meta, 'REJECTED')
              await indexUpdate(pol, id, { status: 'REJECTED', verdict: 'RISKY-REJECTED' })
              await auditAppend(pol, { event: 'REJECT', id, ts: new Date().toISOString(), actor: outcome === 'rejected' ? 'user' : 'system', reason: 'risky command not approved' })
              return cleanJson({ command_id: id, status: 'REJECTED', verdict: 'RISKY', risk_level: review.risk_level, checks: review.checks, review_reason: review.reason, reason: 'the risky command was not approved' + (outcome === 'unavailable' ? ' (no approval answerer available — fail closed)' : ' by the user') })
            }
          } else {
            await updateMetaStatus(pol, dir, meta, 'APPROVED')
            await indexUpdate(pol, id, { status: 'APPROVED', verdict: 'APPROVED' })
            await auditAppend(pol, { event: 'APPROVE', id, ts: new Date().toISOString(), actor: 'deterministic-reviewer' })
          }

          const execution = await executeApproved(pol, dir, meta, exec && exec.agent, info)
          console.log('[cmdq] EXECUTED ' + id + ' exit=' + execution.exit_code)
          return cleanJson({
            command_id: id,
            status: 'EXECUTED',
            verdict: 'APPROVED',
            risk_level: review.risk_level,
            checks: review.checks,
            review_reason: review.reason,
            execution,
          }
        } catch (e) {
          return { error: 'review failed: ' + errMsg(e) }
        }
      },
    })

    const statusTool = harness.defineTool({
      name: 'command_status',
      description: 'Read the current status, review verdict, and execution outcome of one quarantined command by its command_id.',
      parameters: {
        type: 'object',
        properties: {
          command_id: { type: 'string', description: 'The command_id returned by submit_command.' },
        },
        additionalProperties: true,
        required: ['command_id'],
      },
      output: { schema: { type: 'json' }, render: renderJson },
      timeoutMs: 15000,
      execute: async (args, exec) => {
        try {
          const id = String(args.command_id || '').toLowerCase()
          if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) return { error: 'invalid command_id format' }
          const pol = sessionPolicy(exec && exec.agent)
          const dir = qRoot(pol) + '\\' + id
          const meta = await readJsonFile(pol, dir + '\\meta.json')
          if (meta === undefined) return { error: 'no such command "' + id + '" in the quarantine zone' }
          const review = await readJsonFile(pol, dir + '\\review.json')
          const audit = await readJsonFile(pol, dir + '\\audit.json')
          return cleanJson({
            command_id: id,
            status: meta.status,
            tool: meta.tool,
            intent: meta.intent,
            submitted_at: meta.created_at,
            working_directory: meta.working_directory,
            sandbox_mode: meta.sandbox_mode,
            review: review === undefined ? undefined : { verdict: review.verdict, risk_level: review.risk_level, syntax_check: review.syntax_check, static_check: review.static_check, reason: review.reason, reviewed_at: review.reviewed_at, user_approval: review.user_approval },
            execution: audit === undefined ? undefined : { exit_code: audit.exit_code, executed_at: audit.executed_at, duration_ms: audit.duration_ms, timed_out: audit.timed_out, sandbox: audit.sandbox, stdout_file: dir + '\\' + audit.stdout_file, stderr_file: dir + '\\' + audit.stderr_file },
          }
        } catch (e) {
          return { error: 'status failed: ' + errMsg(e) }
        }
      },
    })

    const listTool = harness.defineTool({
      name: 'list_commands',
      description: 'List every command ever submitted to the quarantine zone in this workspace, newest first, with its current status.',
      parameters: { type: 'object', properties: {}, additionalProperties: true },
      output: { schema: { type: 'json' }, render: renderJson },
      timeoutMs: 15000,
      execute: async (_args, exec) => {
        try {
          const pol = sessionPolicy(exec && exec.agent)
          const root = qRoot(pol)
          const idx = (await readJsonFile(pol, root + '\\index.json')) || {}
          const entries = []
          for (const id in idx) {
            if (!Object.prototype.hasOwnProperty.call(idx, id)) continue
            const e = idx[id]
            const entry = { command_id: id, status: e.status || 'UNKNOWN', tool: e.tool || '', intent: e.intent || '' }
            if (e.submitted_at !== undefined) entry.submitted_at = e.submitted_at
            if (e.verdict !== undefined) entry.verdict = e.verdict
            if (e.exit_code !== undefined) entry.exit_code = e.exit_code
            if (e.updated_at !== undefined) entry.updated_at = e.updated_at
            entries.push(entry)
          }
          entries.sort((a, b) => String(b.submitted_at).localeCompare(String(a.submitted_at)))
          return cleanJson({ quarantine_root: root, audit_log: root + '\\audit\\audit.jsonl', count: entries.length, commands: entries.slice(0, 100) })
        } catch (e) {
          return { error: 'list failed: ' + errMsg(e) }
        }
      },
    })

    for (const tool of [submitTool, reviewTool, statusTool, listTool]) {
      ctx.effect(() => harness.registerTool(ctx, tool))
    }

    /* ---------------- isolation enforcement ---------------- */

    const SUBAGENT_TOOL_RE = /^(subagent|subagent_fork|workflow|ralph)$/i
    const SHELL_CANDIDATE_RE = /^(pwsh|powershell|bash|zsh|sh|cmd|shell|run_shell|terminal|exec)$/i

    /* Command-execution tools discoverable in this deployment. The user can
     * narrow this list in the settings panel (toolDenyList); the empty list
     * means "intercept every discovered candidate". */
    function discoverCommandTools() {
      const names = []
      try {
        const schemas = ctx.tools.schemas()
        for (const s of schemas) {
          if (s && typeof s.name === 'string' && SHELL_CANDIDATE_RE.test(s.name)) names.push(s.name)
        }
      } catch (e) { /* facade unavailable */ }
      names.sort()
      return names
    }

    function effectiveDenySet() {
      const cfg = liveConfig
      if (Array.isArray(cfg.toolDenyList) && cfg.toolDenyList.length > 0) {
        return cfg.toolDenyList.map(n => String(n).toLowerCase())
      }
      return discoverCommandTools().map(n => n.toLowerCase())
    }

    /* Is the calling agent (or one of its ancestors) under review right now? */
    function isReviewedNow(agent) {
      const cfg = liveConfig
      if (cfg.reviewScope === 'off') return false
      if (cfg.reviewScope === 'global') return true
      if (cfg.reviewScope === 'per-session') {
        if (agent === undefined || agent === null) return false
        const list = Array.isArray(cfg.reviewedSessions) ? cfg.reviewedSessions : []
        if (list.length === 0) return false
        let cur = agent
        for (let depth = 0; depth < 8 && cur !== undefined && cur !== null; depth++) {
          try {
            const sid = cur.session && cur.session.id ? String(cur.session.id) : ''
            if (sid !== '' && list.indexOf(sid) !== -1) return true
            const hdr = cur.session && cur.session.header
            const pid = hdr ? hdr.parentSession : undefined
            if (!pid) return false
            if (agents === undefined) return false
            const parent = agents.get(pid)
            if (parent === undefined) return false
            cur = parent
          } catch (e) {
            return false
          }
        }
        return false
      }
      return true /* unknown scope → fail closed */
    }

    /* Authoritative gate with layered scope:
     *   global       → intercept in every session/agent/preset
     *   per-session  → intercept only in reviewed sessions and their lineage
     *   off          → no interception anywhere */
    ctx.on('tools/pre-execute', (exec, next) => {
      if (exec !== null && typeof exec === 'object' && typeof exec.name === 'string') {
        if (!isReviewedNow(exec.agent)) return next()
        if (liveConfig.interceptTools !== false && effectiveDenySet().indexOf(String(exec.name).toLowerCase()) !== -1) {
          return {
            kind: 'deny',
            reason: 'Direct command execution is intercepted by the command quarantine plugin (review scope: '
              + liveConfig.reviewScope + '). '
              + 'Submit the command with submit_command(script, tool, intent, ...) and run the review with request_review(command_id).',
          }
        }
        if (liveConfig.blockSubagents !== false && SUBAGENT_TOOL_RE.test(exec.name)) {
          return {
            kind: 'deny',
            reason: 'Spawning sub-agents is blocked by the command quarantine plugin (Phase 4 escape-channel guard), '
              + 'because a spawned agent would regain direct command execution. Do the work in this session; '
              + 'any command execution must go through submit_command / request_review. '
              + '(Re-enable in Settings → Plugins → Command Quarantine.)',
          }
        }
      }
      return next()
    })

    /* Presentational layer: hide the intercepted tools from the model's tool
     * list only while global review is on. In per-session/off scopes the tools
     * stay visible and the pre-execute gate decides per call. */
    ctx.on('system-prompt/assemble', async (assembly, _context, next) => {
      const a = await next()
      const scope = liveConfig.reviewScope
      const hideTools = scope === 'global' || scope === undefined
      if (hideTools && a !== null && typeof a === 'object' && Array.isArray(a.tools)) {
        a.tools = a.tools.filter(t => !(t !== null && typeof t === 'object' && typeof t.name === 'string' && SHELL_TOOL_RE.test(t.name)))
      }
      return a
    })

    /* Tell the model how the quarantine workflow operates (dynamic per scope). */
    if (systemPrompt !== undefined) {
      ctx.effect(() => systemPrompt.section({
        name: 'command-quarantine-policy',
        order: 100,
        text: () => {
          const scope = liveConfig.reviewScope
          if (scope === 'off') {
            return '[COMMAND QUARANTINE — INTERCEPTION OFF]\n'
              + 'Command interception is currently DISABLED for every session (review scope: off). '
              + 'Direct command tools are available; nothing is reviewed. '
              + 'Turn it back on in Settings → Plugins → Command Quarantine.'
          }
          if (scope === 'per-session') {
            return '[COMMAND QUARANTINE — SESSION-SCOPED]\n'
              + 'Direct command execution is intercepted only in sessions whose review switch is ON (composer row). '
              + 'In a reviewed session, submit commands with submit_command(script, tool, intent, ...) and run request_review(command_id); '
              + 'APPROVED executes automatically, RISKY asks the user, REJECTED returns the reason. '
              + 'Everything is audited under <workspace>\\quarantine\\ (audit\\audit.jsonl + per-command logs).'
          }
          return '[COMMAND QUARANTINE — ACTIVE (GLOBAL)]\n'
            + 'Direct shell execution is DISABLED in every session. To run any command:\n'
            + '1. submit_command(script, tool, intent, working_directory?, timeout_seconds?, sandbox_mode?) returns a command_id. Nothing executes.\n'
            + '2. request_review(command_id) runs deterministic pre-checks (syntax + static safety rules) and then an independent LLM reviewer sub-agent issues the final verdict:\n'
            + '   - APPROVED: the command executes automatically and stdout/stderr are returned to you.\n'
            + '   - RISKY: the user is asked to approve; approval executes it, rejection kills it.\n'
            + '   - REJECTED: the reason is returned; fix the script and submit a new command.\n'
            + 'Allowed interpreters are probed on this host: "powershell" (.ps1) and "cmd" (.bat), plus "python"/"bash" when installed.\n'
            + 'working_directory must stay inside the session workspace. sandbox_mode defaults to "read-only"; request "workspace-write" only when the script must write workspace files.\n'
            + 'Everything is audited under <workspace>\\quarantine\\ (audit\\audit.jsonl + per-command stdout/stderr logs).\n'
            + 'Use command_status(command_id) to inspect one command and list_commands() to list them all.'
        },
      }))
    }

    /* ---------------- Phase 3+4: settings entry + pending-approval RPC ---------------- */

    function candidateRoots() {
      const roots = []
      if (cachedWorkspaceRoot !== undefined && cachedWorkspaceRoot !== null && cachedWorkspaceRoot !== '') roots.push(cachedWorkspaceRoot)
      try {
        if (agents !== undefined) {
          const live = agents.list()
          for (let i = 0; i < live.length; i++) {
            try {
              const p = sessionPolicy(live[i])
              if (p && p.workspaceRoot && roots.indexOf(p.workspaceRoot) === -1) roots.push(p.workspaceRoot)
            } catch (e) { /* next agent */ }
          }
        }
      } catch (e) { /* registry unavailable */ }
      try {
        const p0 = sandboxPolicy.resolve()
        if (p0 && p0.workspaceRoot && roots.indexOf(p0.workspaceRoot) === -1) roots.push(p0.workspaceRoot)
      } catch (e) { /* fallback unavailable */ }
      return roots
    }

    function polForRoot(root) {
      return { mode: 'workspace-write', workspaceRoot: root }
    }

    function rpcPol() {
      const roots = candidateRoots()
      if (roots.length > 0) return polForRoot(roots[0])
      try {
        return sandboxPolicy.resolve()
      } catch (e) {
        return sandboxPolicy.resolve({})
      }
    }

    async function findCommandRoot(id) {
      for (const root of candidateRoots()) {
        const p = polForRoot(root)
        const meta = await readJsonFile(p, root + '\\quarantine\\' + id + '\\meta.json')
        if (meta !== undefined) return { pol: p, meta, root }
      }
      return undefined
    }

    async function pendingList(pol) {
      const out = []
      const seen = new Set()
      for (const root of candidateRoots()) {
        const p = polForRoot(root)
        const idx = (await readJsonFile(p, root + '\\quarantine\\index.json')) || {}
        for (const id in idx) {
          if (!Object.prototype.hasOwnProperty.call(idx, id)) continue
          const e = idx[id]
          if (e.status !== 'USER_REVIEW' || seen.has(id)) continue
          seen.add(id)
          const review = await readJsonFile(p, root + '\\quarantine\\' + id + '\\review.json')
          out.push({ command_id: id, tool: e.tool, intent: e.intent, submitted_at: e.submitted_at, reason: review ? review.reason : '' })
        }
      }
      out.sort((a, b) => String(b.submitted_at).localeCompare(String(a.submitted_at)))
      return out
    }

    async function pendingApprove(pol, id) {
      const found = await findCommandRoot(id)
      if (found === undefined) return { ok: false, error: 'no such command' }
      const dir = found.root + '\\quarantine\\' + id
      const fp = found.pol
      const meta = found.meta
      if (meta.status !== 'USER_REVIEW') return { ok: false, error: 'command status is ' + meta.status + ', not USER_REVIEW' }
      const script = await readTextFile(fp, dir + '\\' + meta.script_file)
      if (script === undefined) return { ok: false, error: 'script file missing' }
      if (sha256hex(script) !== meta.script_sha256) return { ok: false, error: 'script hash mismatch' }
      const info = await probeTool(meta.tool)
      if (info === undefined) return { ok: false, error: 'interpreter for "' + meta.tool + '" is not installed on this host' }
      let execPol = fp
      const cfg0 = await readConfig(fp)
      if (cfg0.mainSessionId !== undefined && agents !== undefined) {
        try {
          const mainAgent = agents.get(cfg0.mainSessionId)
          if (mainAgent !== undefined) execPol = sessionPolicy(mainAgent)
        } catch (e) { /* keep the root policy */ }
      }
      const review = (await readJsonFile(fp, dir + '\\review.json')) || { verdict: 'RISKY', reason: '' }
      review.user_approval = { approved_by: 'user', approved_at: new Date().toISOString() }
      await writeJsonFile(fp, dir + '\\review.json', review)
      await updateMetaStatus(fp, dir, meta, 'APPROVED')
      await indexUpdate(fp, id, { status: 'APPROVED', verdict: 'RISKY-APPROVED' })
      await auditAppend(fp, { event: 'APPROVE', id, ts: new Date().toISOString(), actor: 'user' })
      const execution = await executeApproved(execPol, dir, meta, undefined, info)
      return { ok: true, status: 'EXECUTED', exit_code: execution.exit_code, stdout_tail: execution.stdout_tail, stderr_tail: execution.stderr_tail }
    }

    async function pendingReject(pol, id) {
      const found = await findCommandRoot(id)
      if (found === undefined) return { ok: false, error: 'no such command' }
      const dir = found.root + '\\quarantine\\' + id
      const fp = found.pol
      const meta = found.meta
      if (meta.status !== 'USER_REVIEW') return { ok: false, error: 'command status is ' + meta.status + ', not USER_REVIEW' }
      await updateMetaStatus(fp, dir, meta, 'REJECTED')
      await indexUpdate(fp, id, { status: 'REJECTED', verdict: 'RISKY-REJECTED' })
      await auditAppend(fp, { event: 'REJECT', id, ts: new Date().toISOString(), actor: 'user', reason: 'rejected from the plugin settings panel' })
      return { ok: true, status: 'REJECTED' }
    }

    ctx.effect(() => harness.handle('config.get', async () => {
      try {
        const pol = rpcPol()
        const cfg = await readConfig(pol)
        const providers = llm !== undefined ? llm.listProviders().map(p => ({ id: p.id, name: p.name })) : []
        return cleanJson({
          reviewScope: cfg.reviewScope,
          reviewedSessions: Array.isArray(cfg.reviewedSessions) ? cfg.reviewedSessions : [],
          llmReview: cfg.llmReview !== false,
          reviewerMode: cfg.reviewerMode,
          reviewerProvider: cfg.reviewerProvider || '',
          reviewerModel: cfg.reviewerModel || '',
          blockSubagents: cfg.blockSubagents !== false,
          interceptTools: cfg.interceptTools !== false,
          toolCandidates: discoverCommandTools(),
          toolDenyList: Array.isArray(cfg.toolDenyList) ? cfg.toolDenyList : [],
          providers,
          note: 'Settings are stored in <workspace>\\quarantine\\config.json and apply to this workspace.',
        })
      } catch (e) {
        return { error: errMsg(e) }
      }
    }))

    ctx.effect(() => harness.handle('config.set', async (args) => {
      try {
        const pol = rpcPol()
        const patch = {}
        if (args !== null && typeof args === 'object') {
          if (args.reviewScope === 'global' || args.reviewScope === 'per-session' || args.reviewScope === 'off') patch.reviewScope = args.reviewScope
          if (typeof args.llmReview === 'boolean') patch.llmReview = args.llmReview
          if (args.reviewerMode === 'follow-session' || args.reviewerMode === 'custom') patch.reviewerMode = args.reviewerMode
          if (typeof args.reviewerProvider === 'string') patch.reviewerProvider = args.reviewerProvider
          if (typeof args.reviewerModel === 'string') patch.reviewerModel = args.reviewerModel
          if (typeof args.blockSubagents === 'boolean') patch.blockSubagents = args.blockSubagents
          if (typeof args.interceptTools === 'boolean') patch.interceptTools = args.interceptTools
          if (Array.isArray(args.toolDenyList)) patch.toolDenyList = args.toolDenyList.map(n => String(n))
        }
        const cfg = await writeConfig(pol, patch)
        return cleanJson({
          ok: true,
          reviewScope: cfg.reviewScope,
          reviewedSessions: Array.isArray(cfg.reviewedSessions) ? cfg.reviewedSessions : [],
          llmReview: cfg.llmReview !== false,
          reviewerMode: cfg.reviewerMode,
          reviewerProvider: cfg.reviewerProvider || '',
          reviewerModel: cfg.reviewerModel || '',
          blockSubagents: cfg.blockSubagents !== false,
          interceptTools: cfg.interceptTools !== false,
          toolDenyList: Array.isArray(cfg.toolDenyList) ? cfg.toolDenyList : [],
        })
      } catch (e) {
        return { error: errMsg(e) }
      }
    }))

    ctx.effect(() => harness.handle('session.get', async (args) => {
      try {
        const sessionId = args !== null && typeof args === 'object' ? String(args.sessionId || '') : ''
        if (sessionId === '') return { error: 'sessionId required' }
        const pol = rpcPol()
        const cfg = await readConfig(pol)
        const list = Array.isArray(cfg.reviewedSessions) ? cfg.reviewedSessions : []
        return cleanJson({
          reviewScope: cfg.reviewScope,
          reviewed: list.indexOf(sessionId) !== -1,
        })
      } catch (e) {
        return { error: errMsg(e) }
      }
    }))

    ctx.effect(() => harness.handle('session.set', async (args) => {
      try {
        const sessionId = args !== null && typeof args === 'object' ? String(args.sessionId || '') : ''
        const reviewed = args !== null && typeof args === 'object' ? args.reviewed === true : false
        if (sessionId === '') return { error: 'sessionId required' }
        const pol = rpcPol()
        const cfg = await readConfig(pol)
        const list = Array.isArray(cfg.reviewedSessions) ? cfg.reviewedSessions.slice() : []
        const idx = list.indexOf(sessionId)
        if (reviewed && idx === -1) list.push(sessionId)
        if (!reviewed && idx !== -1) list.splice(idx, 1)
        const next = await writeConfig(pol, { reviewedSessions: list, reviewScope: reviewed ? 'per-session' : cfg.reviewScope })
        return cleanJson({ ok: true, reviewScope: next.reviewScope, reviewed, reviewedSessions: Array.isArray(next.reviewedSessions) ? next.reviewedSessions : [] })
      } catch (e) {
        return { error: errMsg(e) }
      }
    }))

    ctx.effect(() => harness.handle('models.list', async (args) => {
      try {
        if (llm === undefined) return { models: [] }
        const provider = args !== null && typeof args === 'object' ? String(args.provider || '') : ''
        const models = await llm.listModels(provider)
        return { models: models.map(m => ({ id: m.id, name: m.name })) }
      } catch (e) {
        return { error: errMsg(e) }
      }
    }))

    ctx.effect(() => harness.handle('pending.list', async () => {
      try {
        return cleanJson({ pending: await pendingList(rpcPol()) })
      } catch (e) {
        return { error: errMsg(e) }
      }
    }))

    ctx.effect(() => harness.handle('pending.approve', async (args) => {
      try {
        const id = String((args !== null && typeof args === 'object' ? args.command_id : '') || '').toLowerCase()
        if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) return { ok: false, error: 'invalid command_id' }
        return await pendingApprove(rpcPol(), id)
      } catch (e) {
        return { ok: false, error: errMsg(e) }
      }
    }))

    ctx.effect(() => harness.handle('pending.reject', async (args) => {
      try {
        const id = String((args !== null && typeof args === 'object' ? args.command_id : '') || '').toLowerCase()
        if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) return { ok: false, error: 'invalid command_id' }
        return await pendingReject(rpcPol(), id)
      } catch (e) {
        return { ok: false, error: errMsg(e) }
      }
    }))

    console.log('[cmdq] command quarantine active; root will be <workspace>\\' + QUARANTINE_DIR_NAME)
  },
}
