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
  <ul id="connect-switch" class="tab2" :class="{ red: tab === 'known' }">
    <li :class="{ active: tab === 'new' }" @click="switchTab('new')">
      新主机
    </li>

    <li :class="{ active: tab === 'known' }" @click="switchTab('known')">
      保存的主机 <span class="label">{{ knownsLength }}</span>
    </li>
  </ul>
</template>

<script>
import "./connect_switch.css";

export default {
  props: {
    tab: {
      type: String,
      default: "new",
    },
    knownsLength: {
      type: Number,
      default: 0,
    },
  },
  methods: {
    switchTab(to) {
      this.$emit("switch", to);
    },
  },
};
</script>
