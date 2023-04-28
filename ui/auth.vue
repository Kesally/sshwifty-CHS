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
  <div id="auth">
    <div id="auth-frame">
      <div id="auth-content">
        <h1>需要认证</h1>

        <form class="form1" action="javascript:;" method="POST" @submit="auth">
          <fieldset>
            <div
              class="field"
              :class="{
                error: passphraseErr.length > 0 || error.length > 0,
              }"
            >
              口令

              <input
                v-model="passphrase"
                v-focus="true"
                :disabled="submitting"
                type="password"
                autocomplete="off"
                name="field.field.name"
                placeholder="----------"
                autofocus="autofocus"
              />

              <div
                v-if="passphraseErr.length <= 0 && error.length <= 0"
                class="message"
              >
                需要输入密码才能使用这个
                <a href="https://github.com/nkxingxh/sshwifty">Sshwifty</a>
                实例
              </div>
              <div v-else class="error">
                {{ passphraseErr || error }}
              </div>
            </div>

            <div class="field">
              <button type="submit" :disabled="submitting" @click="auth">
                验证
              </button>
            </div>
          </fieldset>
        </form>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  directives: {
    focus: {
      inserted(el, binding) {
        if (!binding.value) {
          return;
        }

        el.focus();
      },
    },
  },
  props: {
    error: {
      type: String,
      default: "",
    },
  },
  data() {
    return {
      submitting: false,
      passphrase: "",
      passphraseErr: "",
    };
  },
  watch: {
    error(newVal) {
      if (newVal.length > 0) {
        this.submitting = false;
      }
    },
  },
  mounted() {},
  methods: {
    auth() {
      if (this.passphrase.length <= 0) {
        this.passphraseErr = "口令不能为空";

        return;
      }

      if (this.submitting) {
        return;
      }

      this.submitting = true;

      this.passphraseErr = "";

      this.$emit("auth", this.passphrase);
    },
  },
};
</script>
