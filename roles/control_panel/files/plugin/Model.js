// SPDX-License-Identifier: Apache-2.0
// D-38: parse and bound the status document written by aegis-status (root).
// Everything here ends up in Text items set to Text.PlainText; this file only
// makes sure the shapes and sizes are what the panel expects.
.pragma library

var MAX_COMPONENTS = 30
var MAX_ISSUES = 10
var MAX_TEXT = 300
var ID_RE = /^[a-z][a-z0-9-]{0,31}$/
var STATES = ["ok", "off", "unknown", "paused", "disabled", "warn", "fail"]

function clip(value, limit) {
  var text = typeof value === "string" ? value : ""
  text = text.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "?")
  return text.length > limit ? text.substring(0, limit - 1) + "…" : text
}

function num(value) {
  var n = Number(value)
  return isFinite(n) && n >= 0 ? Math.floor(n) : 0
}

function isComponentId(value) {
  return typeof value === "string" && ID_RE.test(value)
}

function parseStatus(raw) {
  var doc
  try {
    doc = JSON.parse(String(raw || ""))
  } catch (e) {
    return { ok: false }
  }
  if (!doc || doc.version !== 1 || !Array.isArray(doc.components)) return { ok: false }
  var components = []
  for (var i = 0; i < doc.components.length && components.length < MAX_COMPONENTS; i++) {
    var c = doc.components[i]
    if (!c || !(isComponentId(c.id) || c.id === "other")) continue
    var state = STATES.indexOf(c.state) >= 0 ? c.state : "unknown"
    var counts = c.counts || {}
    var actions = c.actions || {}
    var issues = []
    var raw_issues = Array.isArray(c.issues) ? c.issues : []
    for (var j = 0; j < raw_issues.length && issues.length < MAX_ISSUES; j++) {
      var f = raw_issues[j] || {}
      issues.push({ id: clip(f.id, 80), status: clip(f.status, 10), detail: clip(f.detail, MAX_TEXT) })
    }
    components.push({
      id: c.id,
      name: clip(c.name, 60) || c.id,
      state: state,
      warn: num(counts.WARN),
      fail: num(counts.FAIL),
      pausedUntil: num(c.paused_until),
      issues: issues,
      canPause: actions.pause === true && isComponentId(c.id),
      canResume: actions.resume === true && isComponentId(c.id),
      canDisable: actions.disable === true && isComponentId(c.id),
      canLogs: actions.logs === true && isComponentId(c.id)
    })
  }
  var worst = STATES.indexOf(doc.worst) >= 0 ? doc.worst : "unknown"
  return { ok: true, worst: worst, generated: num(doc.generated), components: components }
}

function summary(components) {
  var warn = 0, fail = 0, paused = 0
  for (var i = 0; i < components.length; i++) {
    var s = components[i].state
    if (s === "fail") fail++
    else if (s === "warn") warn++
    else if (s === "paused" || s === "disabled") paused++
  }
  var parts = []
  if (fail) parts.push(fail + " failing")
  if (warn) parts.push(warn + " with warnings")
  if (paused) parts.push(paused + " paused or off")
  return parts.length ? parts.join(", ") : "All components OK"
}

function stateLabel(component, nowSec) {
  if (component.state === "paused" && component.pausedUntil > nowSec) {
    var left = Math.max(1, Math.round((component.pausedUntil - nowSec) / 60))
    return "PAUSED " + left + " min"
  }
  return component.state.toUpperCase()
}
