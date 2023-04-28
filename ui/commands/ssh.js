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

import * as header from "../stream/header.js";
import * as reader from "../stream/reader.js";
import * as stream from "../stream/stream.js";
import * as address from "./address.js";
import * as command from "./commands.js";
import * as common from "./common.js";
import * as controls from "./controls.js";
import * as event from "./events.js";
import Exception from "./exception.js";
import * as history from "./history.js";
import * as presets from "./presets.js";
import * as strings from "./string.js";

const AUTHMETHOD_NONE = 0x00;
const AUTHMETHOD_PASSPHRASE = 0x01;
const AUTHMETHOD_PRIVATE_KEY = 0x02;

const COMMAND_ID = 0x01;

const MAX_USERNAME_LEN = 64;
const MAX_PASSWORD_LEN = 4096;
const DEFAULT_PORT = 22;

const SERVER_REMOTE_STDOUT = 0x00;
const SERVER_REMOTE_STDERR = 0x01;
const SERVER_CONNECT_FAILED = 0x02;
const SERVER_CONNECTED = 0x03;
const SERVER_CONNECT_REQUEST_FINGERPRINT = 0x04;
const SERVER_CONNECT_REQUEST_CREDENTIAL = 0x05;

const CLIENT_DATA_STDIN = 0x00;
const CLIENT_DATA_RESIZE = 0x01;
const CLIENT_CONNECT_RESPOND_FINGERPRINT = 0x02;
const CLIENT_CONNECT_RESPOND_CREDENTIAL = 0x03;

const SERVER_REQUEST_ERROR_BAD_USERNAME = 0x01;
const SERVER_REQUEST_ERROR_BAD_ADDRESS = 0x02;
const SERVER_REQUEST_ERROR_BAD_AUTHMETHOD = 0x03;

const FingerprintPromptVerifyPassed = 0x00;
const FingerprintPromptVerifyNoRecord = 0x01;
const FingerprintPromptVerifyMismatch = 0x02;

const HostMaxSearchResults = 3;

class SSH {
  /**
   * constructor
   *
   * @param {stream.Sender} sd Stream sender
   * @param {object} config configuration
   * @param {object} callbacks Event callbacks
   *
   */
  constructor(sd, config, callbacks) {
    this.sender = sd;
    this.config = config;
    this.connected = false;
    this.events = new event.Events(
      [
        "initialization.failed",
        "initialized",
        "connect.failed",
        "connect.succeed",
        "connect.fingerprint",
        "connect.credential",
        "@stdout",
        "@stderr",
        "close",
        "@completed",
      ],
      callbacks
    );
  }

  /**
   * Send intial request
   *
   * @param {stream.InitialSender} initialSender Initial stream request sender
   *
   */
  run(initialSender) {
    let user = new strings.String(this.config.user),
      userBuf = user.buffer(),
      addr = new address.Address(
        this.config.host.type,
        this.config.host.address,
        this.config.host.port
      ),
      addrBuf = addr.buffer(),
      authMethod = new Uint8Array([this.config.auth]);

    let data = new Uint8Array(userBuf.length + addrBuf.length + 1);

    data.set(userBuf, 0);
    data.set(addrBuf, userBuf.length);
    data.set(authMethod, userBuf.length + addrBuf.length);

    initialSender.send(data);
  }

  /**
   * Receive the initial stream request
   *
   * @param {header.InitialStream} streamInitialHeader Server respond on the
   *                                                   initial stream request
   *
   */
  initialize(streamInitialHeader) {
    if (!streamInitialHeader.success()) {
      this.events.fire("initialization.failed", streamInitialHeader);

      return;
    }

    this.events.fire("initialized", streamInitialHeader);
  }

  /**
   * Tick the command
   *
   * @param {header.Stream} streamHeader Stream data header
   * @param {reader.Limited} rd Data reader
   *
   * @returns {any} The result of the ticking
   *
   * @throws {Exception} When the stream header type is unknown
   *
   */
  tick(streamHeader, rd) {
    switch (streamHeader.marker()) {
      case SERVER_CONNECTED:
        if (!this.connected) {
          this.connected = true;

          return this.events.fire("connect.succeed", rd, this);
        }
        break;

      case SERVER_CONNECT_FAILED:
        if (!this.connected) {
          return this.events.fire("connect.failed", rd);
        }
        break;

      case SERVER_CONNECT_REQUEST_FINGERPRINT:
        if (!this.connected) {
          return this.events.fire("connect.fingerprint", rd, this.sender);
        }
        break;

      case SERVER_CONNECT_REQUEST_CREDENTIAL:
        if (!this.connected) {
          return this.events.fire("connect.credential", rd, this.sender);
        }
        break;

      case SERVER_REMOTE_STDOUT:
        if (this.connected) {
          return this.events.fire("stdout", rd);
        }
        break;

      case SERVER_REMOTE_STDERR:
        if (this.connected) {
          return this.events.fire("stderr", rd);
        }
        break;
    }

    throw new Exception("Unknown stream header marker");
  }

  /**
   * Send close signal to remote
   *
   */
  async sendClose() {
    return await this.sender.close();
  }

  /**
   * Send data to remote
   *
   * @param {Uint8Array} data
   *
   */
  async sendData(data) {
    return this.sender.sendData(CLIENT_DATA_STDIN, data);
  }

  /**
   * Send resize request
   *
   * @param {number} rows
   * @param {number} cols
   *
   */
  async sendResize(rows, cols) {
    let data = new DataView(new ArrayBuffer(4));

    data.setUint16(0, rows);
    data.setUint16(2, cols);

    return this.sender.send(CLIENT_DATA_RESIZE, new Uint8Array(data.buffer));
  }

  /**
   * Close the command
   *
   */
  async close() {
    await this.sendClose();

    return this.events.fire("close");
  }

  /**
   * Tear down the command completely
   *
   */
  completed() {
    return this.events.fire("completed");
  }
}

const initialFieldDef = {
  主机: {
    name: "主机",
    description: "",
    type: "text",
    value: "",
    example: "ssh.vaguly.com:22",
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      if (d.length <= 0) {
        throw new Error("必须指定主机名");
      }

      let addr = common.splitHostPort(d, DEFAULT_PORT);

      if (addr.addr.length <= 0) {
        throw new Error("不能为空");
      }

      if (addr.addr.length > address.MAX_ADDR_LEN) {
        throw new Error(
          "不能超过 " + address.MAX_ADDR_LEN + " 字节"
        );
      }

      if (addr.port <= 0) {
        throw new Error("必须指定端口");
      }

      return "看起来像一个 " + addr.type + " 地址";
    },
  },
  用户名: {
    name: "用户名",
    description: "",
    type: "text",
    value: "",
    example: "root",
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      if (d.length <= 0) {
        throw new Error("必须指定用户名");
      }

      if (d.length > MAX_USERNAME_LEN) {
        throw new Error(
          "用户名不能超过 " + MAX_USERNAME_LEN + " 字节"
        );
      }

      return "我们将以用户 \"" + d + '" 的身份登录';
    },
  },
  编码: {
    name: "编码",
    description: "服务器的字符编码",
    type: "select",
    value: "utf-8",
    example: common.charsetPresets.join(","),
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      for (let i in common.charsetPresets) {
        if (common.charsetPresets[i] !== d) {
          continue;
        }

        return "";
      }

      throw new Error('不支持 "' + d + '" 字符编码');
    },
  },
  提示: {
    name: "提示",
    description: "",
    type: "textdata",
    value:
      "SSH会话是由后端处理的。流量将在后端服务器上解密，然后传回你的客户端。",
    example: "",
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      return "";
    },
  },
  密码: {
    name: "密码",
    description: "",
    type: "password",
    value: "",
    example: "----------",
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      if (d.length <= 0) {
        throw new Error("必须指定密码");
      }

      if (d.length > MAX_PASSWORD_LEN) {
        throw new Error(
          "太长了，不能超过 " + MAX_PASSWORD_LEN + " 字节"
        );
      }

      return "我们将用这个密码登录";
    },
  },
  "私钥": {
    name: "私钥",
    description:
      '例如 <i style="color: #fff; font-style: normal;">' +
      "~/.ssh/id_rsa</i> 里面的那个, 不能被加密<br /><br />" +
      '要解密私钥，请使用命令: <i style="color: #fff;' +
      ' font-style: normal;">ssh-keygen -f /path/to/private_key -p</i><br />' +
      "<br />" +
      "如果将私钥提交给 Sshwifty，强烈建议每个SSH服务器使用不同的私钥。 要生成一个" +
      '新的 SSH 密钥对，请使用命令 <i style="color: #fff; font-style: normal;">' +
      "ssh-keygen -o -f /path/to/my_server_key</i> 并将" +
      '生成的 <i style="color: #fff; font-style: normal;">' +
      "/path/to/my_server_key.pub</i> 文件部署到目标SSH服务器上。",
    type: "textfile",
    value: "",
    example: "",
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      if (d.length <= 0) {
        throw new Error("必须指定私钥");
      }

      if (d.length > MAX_PASSWORD_LEN) {
        throw new Error(
          "太长了，不能超过 " + MAX_PASSWORD_LEN + " 字节"
        );
      }

      const lines = d.trim().split("\n");
      let firstLineReaded = false;

      for (let i in lines) {
        if (!firstLineReaded) {
          if (lines[i].indexOf("-") === 0) {
            firstLineReaded = true;

            if (lines[i].indexOf("RSA") <= 0) {
              break;
            }
          }

          continue;
        }

        if (lines[i].indexOf("Proc-Type: 4,ENCRYPTED") === 0) {
          throw new Error("不能使用加密的私钥文件");
        }

        if (lines[i].indexOf(":") > 0) {
          continue;
        }

        if (lines[i].indexOf("MII") < 0) {
          throw new Error("不能使用加密的私钥文件");
        }

        break;
      }

      return "我们将用这个私钥登录";
    },
  },
  身份验证: {
    name: "身份验证",
    description:
      "请确保你所选择的认证方法被服务器支持，否则它将被忽略，并可能导致登录失败。",
    type: "radio",
    value: "",
    example: "密码,私钥,None",
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      switch (d) {
        case "密码":
        case "私钥":
        case "None":
          return "";

        default:
          throw new Error("必须指定验证方法");
      }
    },
  },
  指纹: {
    name: "指纹",
    description:
      "请仔细核实指纹。如果你不知道这个指纹，请取消本次连接，否则中间人可能窃取你的连接凭据。",
    type: "textdata",
    value: "",
    example: "",
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      return "";
    },
  },
};

/**
 * Return auth method from given string
 *
 * @param {string} d string data
 *
 * @returns {number} Auth method
 *
 * @throws {Exception} When auth method is invalid
 *
 */
function getAuthMethodFromStr(d) {
  switch (d) {
    case "None":
      return AUTHMETHOD_NONE;

    case "密码":
      return AUTHMETHOD_PASSPHRASE;

    case "私钥":
      return AUTHMETHOD_PRIVATE_KEY;

    default:
      throw new Exception("未知的身份验证方式");
  }
}

class Wizard {
  /**
   * constructor
   *
   * @param {command.Info} info
   * @param {presets.Preset} preset
   * @param {object} session
   * @param {Array<string>} keptSessions
   * @param {streams.Streams} streams
   * @param {subscribe.Subscribe} subs
   * @param {controls.Controls} controls
   * @param {history.History} history
   *
   */
  constructor(
    info,
    preset,
    session,
    keptSessions,
    streams,
    subs,
    controls,
    history
  ) {
    this.info = info;
    this.preset = preset;
    this.hasStarted = false;
    this.streams = streams;
    this.session = session
      ? session
      : {
          credential: "",
        };
    this.keptSessions = keptSessions;
    this.step = subs;
    this.controls = controls.get("SSH");
    this.history = history;
  }

  run() {
    this.step.resolve(this.stepInitialPrompt());
  }

  started() {
    return this.hasStarted;
  }

  control() {
    return this.controls;
  }

  close() {
    this.step.resolve(
      this.stepErrorDone(
        "操作已取消",
        "操作已取消且未取得任何成果"
      )
    );
  }

  stepErrorDone(title, message) {
    return command.done(false, null, title, message);
  }

  stepSuccessfulDone(data) {
    return command.done(
      true,
      data,
      "成功！",
      "我们已经连接到远程主机"
    );
  }

  stepWaitForAcceptWait() {
    return command.wait(
      "请求中",
      "等待请求被后端接受"
    );
  }

  stepWaitForEstablishWait(host) {
    return command.wait(
      "正在连接 " + host,
      "与远程主机建立连接，可能需要一段时间"
    );
  }

  stepContinueWaitForEstablishWait() {
    return command.wait(
      "连接中",
      "与远程主机建立连接，可能需要一段时间"
    );
  }

  /**
   *
   * @param {stream.Sender} sender
   * @param {object} configInput
   * @param {object} sessionData
   *
   */
  buildCommand(sender, configInput, sessionData) {
    let self = this;

    let config = {
      user: common.strToUint8Array(configInput.user),
      auth: getAuthMethodFromStr(configInput.authentication),
      charset: configInput.charset,
      credential: sessionData.credential,
      host: address.parseHostPort(configInput.host, DEFAULT_PORT),
      fingerprint: configInput.fingerprint,
    };

    // Copy the keptSessions from the record so it will not be overwritten here
    let keptSessions = self.keptSessions ? [].concat(...self.keptSessions) : [];

    return new SSH(sender, config, {
      "initialization.failed"(hd) {
        switch (hd.data()) {
          case SERVER_REQUEST_ERROR_BAD_USERNAME:
            self.step.resolve(
              self.stepErrorDone("Request failed", "Invalid username")
            );
            return;

          case SERVER_REQUEST_ERROR_BAD_ADDRESS:
            self.step.resolve(
              self.stepErrorDone("Request failed", "Invalid address")
            );
            return;

          case SERVER_REQUEST_ERROR_BAD_AUTHMETHOD:
            self.step.resolve(
              self.stepErrorDone("Request failed", "Invalid authication method")
            );
            return;
        }

        self.step.resolve(
          self.stepErrorDone("Request failed", "Unknown error: " + hd.data())
        );
      },
      initialized(hd) {
        self.step.resolve(self.stepWaitForEstablishWait(configInput.host));
      },
      async "connect.failed"(rd) {
        let d = new TextDecoder("utf-8").decode(
          await reader.readCompletely(rd)
        );

        self.step.resolve(self.stepErrorDone("连接失败", d));
      },
      "connect.succeed"(rd, commandHandler) {
        self.connectionSucceed = true;

        self.step.resolve(
          self.stepSuccessfulDone(
            new command.Result(
              configInput.user + "@" + configInput.host,
              self.info,
              self.controls.build({
                charset: configInput.charset,
                send(data) {
                  return commandHandler.sendData(data);
                },
                close() {
                  return commandHandler.sendClose();
                },
                resize(rows, cols) {
                  return commandHandler.sendResize(rows, cols);
                },
                events: commandHandler.events,
              }),
              self.controls.ui()
            )
          )
        );

        self.history.save(
          self.info.name() + ":" + configInput.user + "@" + configInput.host,
          configInput.user + "@" + configInput.host,
          new Date(),
          self.info,
          configInput,
          sessionData,
          keptSessions
        );
      },
      async "connect.fingerprint"(rd, sd) {
        self.step.resolve(
          await self.stepFingerprintPrompt(
            rd,
            sd,
            (v) => {
              if (!configInput.fingerprint) {
                return FingerprintPromptVerifyNoRecord;
              }

              if (configInput.fingerprint === v) {
                return FingerprintPromptVerifyPassed;
              }

              return FingerprintPromptVerifyMismatch;
            },
            (newFingerprint) => {
              configInput.fingerprint = newFingerprint;
            }
          )
        );
      },
      async "connect.credential"(rd, sd) {
        self.step.resolve(
          self.stepCredentialPrompt(rd, sd, config, (newCred, fromPreset) => {
            sessionData.credential = newCred;

            // Save the credential if the credential was from a preset
            if (fromPreset && keptSessions.indexOf("credential") < 0) {
              keptSessions.push("credential");
            }
          })
        );
      },
      "@stdout"(rd) {},
      "@stderr"(rd) {},
      close() {},
      "@completed"() {
        self.step.resolve(
          self.stepErrorDone(
            "操作失败",
            "连接已被取消"
          )
        );
      },
    });
  }

  stepInitialPrompt() {
    let self = this;

    return command.prompt(
      "SSH",
      "安全外壳协议",
      "连接",
      (r) => {
        self.hasStarted = true;

        self.streams.request(COMMAND_ID, (sd) => {
          return self.buildCommand(
            sd,
            {
              user: r.user,
              authentication: r.authentication,
              host: r.host,
              charset: r.encoding,
              fingerprint: self.preset
                ? self.preset.metaDefault("指纹", "")
                : "",
            },
            self.session
          );
        });

        self.step.resolve(self.stepWaitForAcceptWait());
      },
      () => {},
      command.fieldsWithPreset(
        initialFieldDef,
        [
          {
            name: "主机",
            suggestions(input) {
              const hosts = self.history.search(
                "SSH",
                "host",
                input,
                HostMaxSearchResults
              );

              let sugg = [];

              for (let i = 0; i < hosts.length; i++) {
                sugg.push({
                  title: hosts[i].title,
                  value: hosts[i].data.host,
                  meta: {
                    用户名: hosts[i].data.user,
                    身份验证: hosts[i].data.authentication,
                    编码: hosts[i].data.charset,
                  },
                });
              }

              return sugg;
            },
          },
          { name: "用户名" },
          { name: "身份验证" },
          { name: "编码" },
          { name: "提示" },
        ],
        self.preset,
        (r) => {}
      )
    );
  }

  async stepFingerprintPrompt(rd, sd, verify, newFingerprint) {
    const self = this;

    let fingerprintData = new TextDecoder("utf-8").decode(
        await reader.readCompletely(rd)
      ),
      fingerprintChanged = false;

    switch (verify(fingerprintData)) {
      case FingerprintPromptVerifyPassed:
        sd.send(CLIENT_CONNECT_RESPOND_FINGERPRINT, new Uint8Array([0]));

        return self.stepContinueWaitForEstablishWait();

      case FingerprintPromptVerifyMismatch:
        fingerprintChanged = true;
    }

    return command.prompt(
      !fingerprintChanged
        ? "你认识这台服务器吗？"
        : "危险！服务器指纹已改变！",
      !fingerprintChanged
        ? "核实下面显示的服务器指纹"
        : "这是很不常见的。请验证下面的新服务器指纹",
      !fingerprintChanged ? "确认" : "仍然继续",
      (r) => {
        newFingerprint(fingerprintData);

        sd.send(CLIENT_CONNECT_RESPOND_FINGERPRINT, new Uint8Array([0]));

        self.step.resolve(self.stepContinueWaitForEstablishWait());
      },
      () => {
        sd.send(CLIENT_CONNECT_RESPOND_FINGERPRINT, new Uint8Array([1]));

        self.step.resolve(
          command.wait("拒绝中", "正在向后端发送拒绝信号")
        );
      },
      command.fields(initialFieldDef, [
        {
          name: "指纹",
          value: fingerprintData,
        },
      ])
    );
  }

  async stepCredentialPrompt(rd, sd, config, newCredential) {
    const self = this;

    let fields = [];

    if (config.credential.length > 0) {
      sd.send(
        CLIENT_CONNECT_RESPOND_CREDENTIAL,
        new TextEncoder().encode(config.credential)
      );

      return self.stepContinueWaitForEstablishWait();
    }

    switch (config.auth) {
      case AUTHMETHOD_PASSPHRASE:
        fields = [{ name: "密码" }];
        break;

      case AUTHMETHOD_PRIVATE_KEY:
        fields = [{ name: "私钥" }];
        break;

      default:
        throw new Exception(
          '不支持 "' + config.auth + '" 验证方式'
        );
    }

    let presetCredentialUsed = false;
    const inputFields = command.fieldsWithPreset(
      initialFieldDef,
      fields,
      self.preset,
      (r) => {
        if (r !== fields[0].name) {
          return;
        }

        presetCredentialUsed = true;
      }
    );

    return command.prompt(
      "提供凭据",
      "请输入你的凭据",
      "登录",
      (r) => {
        let vv = r[fields[0].name.toLowerCase()];

        sd.send(
          CLIENT_CONNECT_RESPOND_CREDENTIAL,
          new TextEncoder().encode(vv)
        );

        newCredential(vv, presetCredentialUsed);

        self.step.resolve(self.stepContinueWaitForEstablishWait());
      },
      () => {
        sd.close();

        self.step.resolve(
          command.wait(
            "取消登录",
            "正在取消登录请求，请稍等"
          )
        );
      },
      inputFields
    );
  }
}

class Executer extends Wizard {
  /**
   * constructor
   *
   * @param {command.Info} info
   * @param {config} config
   * @param {object} session
   * @param {Array<string>} keptSessions
   * @param {streams.Streams} streams
   * @param {subscribe.Subscribe} subs
   * @param {controls.Controls} controls
   * @param {history.History} history
   *
   */
  constructor(
    info,
    config,
    session,
    keptSessions,
    streams,
    subs,
    controls,
    history
  ) {
    super(
      info,
      presets.emptyPreset(),
      session,
      keptSessions,
      streams,
      subs,
      controls,
      history
    );

    this.config = config;
  }

  stepInitialPrompt() {
    const self = this;

    self.hasStarted = true;

    self.streams.request(COMMAND_ID, (sd) => {
      return self.buildCommand(
        sd,
        {
          user: self.config.user,
          authentication: self.config.authentication,
          host: self.config.host,
          charset: self.config.charset ? self.config.charset : "utf-8",
          fingerprint: self.config.fingerprint,
        },
        self.session
      );
    });

    return self.stepWaitForAcceptWait();
  }
}

export class Command {
  constructor() {}

  id() {
    return COMMAND_ID;
  }

  name() {
    return "SSH";
  }

  description() {
    return "安全外壳协议";
  }

  color() {
    return "#3c8";
  }

  wizard(
    info,
    preset,
    session,
    keptSessions,
    streams,
    subs,
    controls,
    history
  ) {
    return new Wizard(
      info,
      preset,
      session,
      keptSessions,
      streams,
      subs,
      controls,
      history
    );
  }

  execute(
    info,
    config,
    session,
    keptSessions,
    streams,
    subs,
    controls,
    history
  ) {
    return new Executer(
      info,
      config,
      session,
      keptSessions,
      streams,
      subs,
      controls,
      history
    );
  }

  launch(info, launcher, streams, subs, controls, history) {
    const d = launcher.split("|", 3);

    if (d.length < 2) {
      throw new Exception('Given launcher "' + launcher + '" was invalid');
    }

    const userHostName = d[0].match(new RegExp("^(.*)\\@(.*)$"));

    if (!userHostName || userHostName.length !== 3) {
      throw new Exception('Given launcher "' + launcher + '" was malformed');
    }

    let user = userHostName[1],
      host = userHostName[2],
      auth = d[1],
      charset = d.length >= 3 && d[2] ? d[2] : "utf-8"; // RM after depreciation

    try {
      initialFieldDef["用户名"].verify(user);
      initialFieldDef["主机"].verify(host);
      initialFieldDef["身份验证"].verify(auth);
      initialFieldDef["编码"].verify(charset);
    } catch (e) {
      throw new Exception(
        'Given launcher "' + launcher + '" was malformed ' + e
      );
    }

    return this.execute(
      info,
      {
        user: user,
        host: host,
        authentication: auth,
        charset: charset,
      },
      null,
      null,
      streams,
      subs,
      controls,
      history
    );
  }

  launcher(config) {
    return (
      config.user +
      "@" +
      config.host +
      "|" +
      config.authentication +
      "|" +
      (config.charset ? config.charset : "utf-8")
    );
  }

  represet(preset) {
    const host = preset.host();

    if (host.length > 0) {
      preset.insertMeta("主机", host);
    }

    return preset;
  }
}
