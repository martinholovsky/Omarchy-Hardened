// SPDX-License-Identifier: Apache-2.0
// D-38: Aegis status in the bar (a shield, urgent on WARN or FAIL) and a panel
// listing each component with its state, issues and actions. Every Text that
// shows data is Text.PlainText (Omarchy plugin UI safety rules). This panel
// is a convenience: it runs as the user, so the root audit, the journal and
// the drift-check notifications stay authoritative.
import QtQuick
import QtQuick.Controls
import Quickshell
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "Model.js" as Model

Panel {
  id: root
  moduleName: "aegis.status"
  // open/close/toggle over `omarchy-shell aegis.status <verb>` (Panel's IPC).
  ipcTarget: "aegis.status"
  manageIpc: true

  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property bool alarming: aegis.worst === "fail" || aegis.worst === "warn"

  function stateColor(state) {
    if (state === "fail" || state === "warn") return root.urgent
    if (state === "paused" || state === "disabled" || state === "off" || state === "unknown") return root.dim
    return root.foreground
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: if (opened) aegis.refresh()

  Service {
    id: aegis
    settings: root.settings
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: ""  // Nerd Font fa-shield
    active: root.alarming
    dimmed: !aegis.loaded
    tooltipText: "Aegis: " + Model.summary(aegis.components)
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) aegis.refresh()
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: panel.loadedContent
    contentWidth: panel.fittedContentWidth(Style.space(440))
    contentHeight: panel.fittedContentHeight(panel.loadedContentHeight, Style.space(620))

    content: PanelKeyCatcher {
      implicitHeight: column.implicitHeight
      anchors.fill: parent
      onCloseRequested: root.close()
      onTextKey: function(t) {
        if (t === "r" || t === "R") aegis.refresh()
        else if (t === "a" || t === "A") aegis.unlock()
      }

      Flickable {
        id: flick
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: flick.width
          spacing: Style.space(10)

          PanelHero {
            width: parent.width
            title: "Aegis"
            meta: aegis.loaded ? Model.summary(aegis.components) : "Reading status…"
            foreground: root.foreground
            fontFamily: root.fontFamily
            trailingControl: Component {
              Button {
                text: aegis.adminActive ? "Admin on" : "Admin mode"
                iconText: aegis.adminActive ? "" : ""  // unlock / lock
                tooltipText: "Authenticate once; pause and logs then do not ask again for a few minutes. Resume never asks"
                foreground: aegis.adminActive ? root.urgent : root.foreground
                fontFamily: root.fontFamily
                onClicked: aegis.unlock()
              }
            }
          }

          Text {
            textFormat: Text.PlainText
            visible: aegis.actionStatus !== "" || aegis.lastError !== ""
            width: parent.width
            text: aegis.actionStatus !== "" ? aegis.actionStatus : aegis.lastError
            color: aegis.lastError !== "" && aegis.actionStatus === "" ? root.urgent : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          PanelSeparator { foreground: root.foreground }

          Repeater {
            model: aegis.components

            delegate: Column {
              required property var modelData
              width: column.width
              spacing: Style.space(4)

              Item {
                width: parent.width
                implicitHeight: Math.max(nameText.implicitHeight, actions.implicitHeight)

                Text {
                  id: nameText
                  textFormat: Text.PlainText
                  anchors.left: parent.left
                  anchors.verticalCenter: parent.verticalCenter
                  // Leave room for the state and the buttons (VM, 2026-11-21:
                  // a long name ran into "Pause 15m").
                  width: Math.min(implicitWidth,
                                  parent.width - actions.width - stateText.implicitWidth - Style.space(24))
                  elide: Text.ElideRight
                  text: modelData.name
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }

                Text {
                  id: stateText
                  textFormat: Text.PlainText
                  anchors.left: nameText.right
                  anchors.leftMargin: Style.space(8)
                  anchors.verticalCenter: parent.verticalCenter
                  text: Model.stateLabel(modelData, Math.floor(aegis.nowMs / 1000))
                  color: root.stateColor(modelData.state)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                }

                Row {
                  id: actions
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  spacing: Style.space(4)

                  Button {
                    visible: modelData.canPause
                    text: "Pause 15m"
                    tooltipText: "Stop it for 15 minutes; it comes back on its own"
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    fontSize: Style.font.bodySmall
                    onClicked: aegis.pause(modelData.id, 15)
                  }
                  Button {
                    visible: modelData.canResume
                    text: "Resume"
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    fontSize: Style.font.bodySmall
                    onClicked: aegis.resume(modelData.id)
                  }
                  Button {
                    visible: modelData.canLogs
                    text: "Logs"
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    fontSize: Style.font.bodySmall
                    onClicked: aegis.logs(modelData.id)
                  }
                  Button {
                    visible: modelData.canDisable
                    text: "Disable…"
                    tooltipText: "Turn it off until the next playbook run (sudo in a terminal)"
                    foreground: root.urgent
                    fontFamily: root.fontFamily
                    fontSize: Style.font.bodySmall
                    onClicked: aegis.disable(modelData.id)
                  }
                }
              }

              Repeater {
                model: modelData.issues

                delegate: Text {
                  required property var modelData
                  textFormat: Text.PlainText
                  width: column.width
                  leftPadding: Style.space(12)
                  text: modelData.status + "  " + modelData.id + ": " + modelData.detail
                  color: modelData.status === "FAIL" ? root.urgent : root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.WordWrap
                  maximumLineCount: 3
                  elide: Text.ElideRight
                }
              }
            }
          }

          Text {
            textFormat: Text.PlainText
            width: parent.width
            text: "This panel runs as you and can be faked; the audit (sudo omarchy-harden) and the journal are authoritative."
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
          }
        }
      }
    }
  }
}
