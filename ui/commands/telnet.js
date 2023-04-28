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

const COMMAND_ID = 0x00;

const SERVER_INITIAL_ERROR_BAD_ADDRESS = 0x01;

const SERVER_REMOTE_BAND = 0x00;
const SERVER_DIAL_FAILED = 0x01;
const SERVER_DIAL_CONNECTED = 0x02;

const DEFAULT_PORT = 23;

const HostMaxSearchResults = 3;

class Telnet {
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
        "@inband",
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
    let addr = new address.Address(
        this.config.host.type,
        this.config.host.address,
        this.config.host.port
      ),
      addrBuf = addr.buffer();

    let data = new Uint8Array(addrBuf.length);

    data.set(addrBuf, 0);

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
      case SERVER_DIAL_CONNECTED:
        if (!this.connected) {
          this.connected = true;

          return this.events.fire("connect.succeed", rd, this);
        }
        break;

      case SERVER_DIAL_FAILED:
        if (!this.connected) {
          return this.events.fire("connect.failed", rd);
        }
        break;

      case SERVER_REMOTE_BAND:
        if (this.connected) {
          return this.events.fire("inband", rd);
        }
        break;
    }

    throw new Exception("Unknown stream header marker");
  }

  /**
   * Send close signal to remote
   *
   */
  sendClose() {
    return this.sender.close();
  }

  /**
   * Send data to remote
   *
   * @param {Uint8Array} data
   *
   */
  sendData(data) {
    return this.sender.sendData(0x00, data);
  }

  /**
   * Close the command
   *
   */
  close() {
    this.sendClose();

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
    description:
      "正在寻找可以连接的服务器&quest; 要不康康 " +
      '<a href="http://www.telnet.org/htm/places.htm" target="blank">' +
      "telnet.org</a> 的公共服务器。",
    type: "text",
    value: "",
    example: "telnet.vaguly.com:23",
    readonly: false,
    suggestions(input) {
      return [];
    },
    verify(d) {
      if (d.length <= 0) {
        throw new Error("必须输入主机地址");
      }

      let addr = common.splitHostPort(d, DEFAULT_PORT);

      if (addr.addr.length <= 0) {
        throw new Error("不能为空");
      }

      if (addr.addr.length > address.MAX_ADDR_LEN) {
        throw new Error(
          "地址不能超过 " + address.MAX_ADDR_LEN + " 字节"
        );
      }

      if (addr.port <= 0) {
        throw new Error("请指定有效端口");
      }

      return "看起来像一个 " + addr.type + " 地址";
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
};

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
    this.session = session;
    this.keptSessions = keptSessions;
    this.step = subs;
    this.controls = controls.get("Telnet");
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

  /**
   *
   * @param {stream.Sender} sender
   * @param {object} configInput
   * @param {object} sessionData
   *
   */
  buildCommand(sender, configInput, sessionData) {
    let self = this;

    let parsedConfig = {
      host: address.parseHostPort(configInput.host, DEFAULT_PORT),
      charset: configInput.charset,
    };

    // Copy the keptSessions from the record so it will not be overwritten here
    let keptSessions = self.keptSessions ? [].concat(...self.keptSessions) : [];

    return new Telnet(sender, parsedConfig, {
      "initialization.failed"(streamInitialHeader) {
        switch (streamInitialHeader.data()) {
          case SERVER_INITIAL_ERROR_BAD_ADDRESS:
            self.step.resolve(
              self.stepErrorDone("请求被拒绝", "无效的地址")
            );

            return;
        }

        self.step.resolve(
          self.stepErrorDone(
            "请求被拒绝",
            "未知错误码: " + streamInitialHeader.data()
          )
        );
      },
      initialized(streamInitialHeader) {
        self.step.resolve(self.stepWaitForEstablishWait(configInput.host));
      },
      "connect.succeed"(rd, commandHandler) {
        self.step.resolve(
          self.stepSuccessfulDone(
            new command.Result(
              configInput.host,
              self.info,
              self.controls.build({
                charset: parsedConfig.charset,
                send(data) {
                  return commandHandler.sendData(data);
                },
                close() {
                  return commandHandler.sendClose();
                },
                events: commandHandler.events,
              }),
              self.controls.ui()
            )
          )
        );

        self.history.save(
          self.info.name() + ":" + configInput.host,
          configInput.host,
          new Date(),
          self.info,
          configInput,
          sessionData,
          keptSessions
        );
      },
      async "connect.failed"(rd) {
        let readed = await reader.readCompletely(rd),
          message = new TextDecoder("utf-8").decode(readed.buffer);

        self.step.resolve(self.stepErrorDone("连接失败", message));
      },
      "@inband"(rd) {},
      close() {},
      "@completed"() {},
    });
  }

  stepInitialPrompt() {
    const self = this;

    return command.prompt(
      "Telnet",
      "远程终端协议",
      "连接",
      (r) => {
        self.hasStarted = true;

        self.streams.request(COMMAND_ID, (sd) => {
          return self.buildCommand(
            sd,
            {
              host: r.主机,
              charset: r.编码,
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
                "Telnet",
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
                    编码: hosts[i].data.charset,
                  },
                });
              }

              return sugg;
            },
          },
          { name: "编码" },
        ],
        self.preset,
        (r) => {}
      )
    );
  }
}

class Executor extends Wizard {
  /**
   * constructor
   *
   * @param {command.Info} info
   * @param {object} config
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
          host: self.config.host,
          charset: self.config.charset ? self.config.charset : "utf-8",
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
    return "Telnet";
  }

  description() {
    return "远程终端协议";
  }

  color() {
    return "#6ac";
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
    return new Executor(
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
    const d = launcher.split("|", 2);

    if (d.length <= 0) {
      throw new Exception('Given launcher "' + launcher + '" was invalid');
    }

    try {
      initialFieldDef["主机"].verify(d[0]);
    } catch (e) {
      throw new Exception(
        'Given launcher "' + launcher + '" was invalid: ' + e
      );
    }

    let charset = "utf-8";

    if (d.length > 1) {
      // TODO: Remove this check after depreciation period.
      try {
        initialFieldDef["编码"].verify(d[1]);

        charset = d[1];
      } catch (e) {
        throw new Exception(
          'Given launcher "' + launcher + '" was invalid: ' + e
        );
      }
    }

    return this.execute(
      info,
      {
        host: d[0],
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
    return config.host + "|" + (config.charset ? config.charset : "utf-8");
  }

  represet(preset) {
    const host = preset.host();

    if (host.length > 0) {
      preset.insertMeta("主机", host);
    }

    return preset;
  }
}
