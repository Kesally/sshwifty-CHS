<!--
// Sshwifty - A Web SSH client
//
// Copyright (C) 2019-2023 Ni Rui <ranqus@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
-->

<template>
  <window
    id="connect"
    flash-class="home-window-display"
    :display="display"
    @display="$emit('display', $event)"
  >
    <div id="connect-frame">
      <h1 class="window-title">建立一个新连接</h1>

      <slot v-if="inputting"></slot>

      <connect-switch
        v-if="!inputting"
        :knowns-length="knowns.length"
        :tab="tab"
        @switch="switchTab"
      ></connect-switch>

      <connect-new
        v-if="tab === 'new' && !inputting"
        :connectors="connectors"
        @select="selectConnector"
      ></connect-new>

      <connect-known
        v-if="tab === 'known' && !inputting"
        :presets="presets"
        :restricted-to-presets="restrictedToPresets"
        :knowns="knowns"
        :launcher-builder="knownsLauncherBuilder"
        :knowns-export="knownsExport"
        :knowns-import="knownsImport"
        @select="selectKnown"
        @select-preset="selectPreset"
        @remove="removeKnown"
        @clear-session="clearSessionKnown"
      ></connect-known>

      <div id="connect-warning">
        <span id="connect-warning-icon" class="icon icon-warning1"></span>
        <div id="connect-warning-msg">
          <p>
            <strong>不安全的服务可能会窃取你的凭据。</strong>
            在使用该服务之前，一定要检查其安全性。
          </p>

          <p>
            Sshwifty 是一个免费软件，你可以把它部署在你自己信任的基础设施上。
            <a href="https://github.com/nkxingxh/sshwifty" target="_blank"
              >了解更多</a
            >
          </p>
        </div>
      </div>

      <div v-if="busy" id="connect-busy-overlay"></div>
    </div>
  </window>
</template>

<script>
import "./connect.css";

import Window from "./window.vue";
import ConnectSwitch from "./connect_switch.vue";
import ConnectKnown from "./connect_known.vue";
import ConnectNew from "./connect_new.vue";

export default {
  components: {
    window: Window,
    "connect-switch": ConnectSwitch,
    "connect-known": ConnectKnown,
    "connect-new": ConnectNew,
  },
  props: {
    display: {
      type: Boolean,
      default: false,
    },
    inputting: {
      type: Boolean,
      default: false,
    },
    presets: {
      type: Array,
      default: () => [],
    },
    restrictedToPresets: {
      type: Boolean,
      default: () => false,
    },
    knowns: {
      type: Array,
      default: () => [],
    },
    knownsLauncherBuilder: {
      type: Function,
      default: () => [],
    },
    knownsExport: {
      type: Function,
      default: () => [],
    },
    knownsImport: {
      type: Function,
      default: () => [],
    },
    connectors: {
      type: Array,
      default: () => [],
    },
    busy: {
      type: Boolean,
      default: false,
    },
  },
  data() {
    return {
      tab: !this.restrictedToPresets ? "new" : "known",
      canSelect: true,
    };
  },
  methods: {
    switchTab(to) {
      if (this.inputting) {
        return;
      }

      this.tab = to;
    },
    selectConnector(connector) {
      if (this.inputting) {
        return;
      }

      this.$emit("connector-select", connector);
    },
    selectKnown(known) {
      if (this.inputting) {
        return;
      }

      this.$emit("known-select", known);
    },
    removeKnown(uid) {
      if (this.inputting) {
        return;
      }

      this.$emit("known-remove", uid);
    },
    selectPreset(preset) {
      if (this.inputting) {
        return;
      }

      this.$emit("preset-select", preset);
    },
    clearSessionKnown(uid) {
      if (this.inputting) {
        return;
      }

      this.$emit("known-clear-session", uid);
    },
  },
};
</script>
