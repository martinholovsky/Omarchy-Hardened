// SPDX-License-Identifier: Apache-2.0
// D-38: reads the status through `aegis status --json` and starts actions.
// Privileged actions go through `aegis`, which runs pkexec (polkit prompt in
// the shell) or opens a terminal for sudo. Nothing here is a shell command:
// every Process and execDetached call takes an argv list, and component ids
// are checked against Model.isComponentId first.
import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model

Item {
  id: root

  property var settings: ({})
  property bool loaded: false
  property string worst: "unknown"
  property var components: []
  property string lastError: ""
  property string actionStatus: ""
  // Admin mode is shown for as long as polkit is expected to keep the
  // authorization (auth_admin_keep, "e.g. five minutes" in polkit(8)). This
  // is a display hint only; polkit decides.
  property double adminUntil: 0
  property double nowMs: Date.now()
  readonly property bool adminActive: adminUntil > nowMs
  readonly property int refreshIntervalSec: intSetting("refreshIntervalSec", 20, 5, 600)
  readonly property bool busy: actionProcess.running

  property string _out: ""
  property string _err: ""
  property string _pendingAction: ""

  function intSetting(name, fallback, min, max) {
    var value = settings ? settings[name] : undefined
    var n = parseInt(String(value === undefined || value === null ? fallback : value), 10)
    if (!isFinite(n)) n = fallback
    return Math.max(min, Math.min(max, n))
  }

  function refresh() {
    if (statusProcess.running) return
    _out = ""
    _err = ""
    statusProcess.command = ["aegis", "status", "--json"]
    statusProcess.running = true
  }

  function apply(raw) {
    var parsed = Model.parseStatus(raw)
    if (!parsed.ok) {
      lastError = "Cannot read the Aegis status"
      return
    }
    worst = parsed.worst
    components = parsed.components
    loaded = true
    lastError = ""
  }

  function run(verb, args) {
    if (actionProcess.running) return
    _pendingAction = verb
    actionStatus = verb === "unlock" ? "Waiting for authentication…" : "Working…"
    actionProcess.command = ["aegis", verb].concat(args)
    actionProcess.running = true
  }

  function unlock() { run("unlock", []) }

  function pause(id, minutes) {
    if (!Model.isComponentId(id)) return
    run("pause", [id, String(Math.max(1, Math.min(120, Math.floor(minutes))))])
  }

  function resume(id) {
    if (Model.isComponentId(id)) run("resume", [id])
  }

  // Logs and disable open a terminal: logs page through less, disable asks
  // for sudo (key and password, D-04).
  function openTerminal(verb, id) {
    if (!Model.isComponentId(id)) return
    Quickshell.execDetached(["uwsm-app", "--", "xdg-terminal-exec", "--app-id=org.omarchy.terminal",
                             "--title=Aegis", "-e", "aegis", verb, id, "--wait"])
  }

  function logs(id) { openTerminal("logs", id) }
  function disable(id) { openTerminal("disable", id) }

  Timer {
    interval: root.refreshIntervalSec * 1000
    repeat: true
    running: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  Timer {
    interval: 1000
    repeat: true
    running: root.adminUntil > 0
    onTriggered: {
      root.nowMs = Date.now()
      if (!root.adminActive) root.adminUntil = 0
    }
  }

  Timer {
    id: clearStatus
    interval: 2500
    onTriggered: root.actionStatus = ""
  }

  Process {
    id: statusProcess
    running: false
    command: []
    stdout: StdioCollector { id: statusOut; waitForEnd: true; onStreamFinished: root._out = text }
    stderr: StdioCollector { id: statusErr; waitForEnd: true; onStreamFinished: root._err = text }
    onExited: function(exitCode) {
      if (exitCode === 0) root.apply(String(statusOut.text || root._out || ""))
      else root.lastError = Model.clip(String(statusErr.text || root._err || "aegis status failed"), 200)
    }
  }

  Process {
    id: actionProcess
    running: false
    command: []
    stdout: StdioCollector { id: actionOut; waitForEnd: true }
    stderr: StdioCollector { id: actionErr; waitForEnd: true }
    onExited: function(exitCode) {
      if (exitCode === 0) {
        if (root._pendingAction === "unlock") {
          root.adminUntil = Date.now() + 5 * 60 * 1000
          root.nowMs = Date.now()
        }
        root.actionStatus = "Done"
      } else {
        // 126/127: polkit dismissed or not authorized.
        root.actionStatus = exitCode === 126 || exitCode === 127
          ? "Not authorized"
          : Model.clip(String(actionErr.text || "Action failed"), 200)
      }
      clearStatus.restart()
      root.refresh()
    }
  }
}
