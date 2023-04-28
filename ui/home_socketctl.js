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

import * as history from "./history.js";
import { ECHO_FAILED } from "./socket.js";

export function build(ctx) {
  const connectionStatusNotConnected = "Sshwifty 已准备进行连接";
  const connectionStatusConnecting =
    "正在连接到 Sshwifty 后端服务器。通常不会超过几秒钟";
  const connectionStatusDisconnected =
    "Sshwifty 与它的后端服务器断开了连接";
  const connectionStatusConnected =
    "Sshwifty 已经连接到后端服务器, 可以进行操作";
  const connectionStatusUnmeasurable =
    "无法测量连接延迟。连接可能非常繁忙或已经丢失";

  const connectionDelayGood =
    "连接延迟很低，操作应该是非常灵敏的";
  const connectionDelayFair =
    "遇到轻微的连接延迟，操作应在合理的时间内得到响应";
  const connectionDelayMedian =
    "遇到中等的连接延迟，考虑放慢输入速度，避免误操作。";
  const connectionDelayHeavy =
    "遇到较高的连接延迟，操作可能在任何时候冻结。请考虑暂停你的输入，直到远程主机有反应。";

  const buildEmptyHistory = () => {
    let r = [];

    for (let i = 0; i < 32; i++) {
      r.push({ data: 0, class: "" });
    }

    return r;
  };

  let isClosed = false,
    inboundPerSecond = 0,
    outboundPerSecond = 0,
    trafficPreSecondNextUpdate = new Date(),
    inboundPre10Seconds = 0,
    outboundPre10Seconds = 0,
    trafficPre10sNextUpdate = new Date(),
    inboundHistory = new history.Records(buildEmptyHistory()),
    outboundHistory = new history.Records(buildEmptyHistory()),
    trafficSamples = 0;

  let delayHistory = new history.Records(buildEmptyHistory()),
    delaySamples = 0,
    delayPerInterval = 0;

  return {
    update(time) {
      if (isClosed) {
        return;
      }

      if (time >= trafficPreSecondNextUpdate) {
        trafficPreSecondNextUpdate = new Date(time.getTime() + 1000);
        inboundPre10Seconds += inboundPerSecond;
        outboundPre10Seconds += outboundPerSecond;

        this.status.inbound = inboundPerSecond;
        this.status.outbound = outboundPerSecond;

        inboundPerSecond = 0;
        outboundPerSecond = 0;

        trafficSamples++;
      }

      if (time >= trafficPre10sNextUpdate) {
        trafficPre10sNextUpdate = new Date(time.getTime() + 10000);

        if (trafficSamples > 0) {
          inboundHistory.update(inboundPre10Seconds / trafficSamples);
          outboundHistory.update(outboundPre10Seconds / trafficSamples);

          inboundPre10Seconds = 0;
          outboundPre10Seconds = 0;
          trafficSamples = 0;
        }

        if (delaySamples > 0) {
          delayHistory.update(delayPerInterval / delaySamples);

          delaySamples = 0;
          delayPerInterval = 0;
        }
      }
    },
    classStyle: "",
    windowClass: "",
    message: "",
    status: {
      description: connectionStatusNotConnected,
      delay: 0,
      delayHistory: delayHistory.get(),
      inbound: 0,
      inboundHistory: inboundHistory.get(),
      outbound: 0,
      outboundHistory: outboundHistory.get(),
    },
    connecting() {
      isClosed = false;

      this.message = "--";
      this.classStyle = "working";
      this.windowClass = "";
      this.status.description = connectionStatusConnecting;
    },
    connected() {
      isClosed = false;

      this.message = "??";
      this.classStyle = "working";
      this.windowClass = "";
      this.status.description = connectionStatusConnected;
    },
    traffic(inb, outb) {
      inboundPerSecond += inb;
      outboundPerSecond += outb;
    },
    echo(delay) {
      delayPerInterval += delay > 0 ? delay : 0;
      delaySamples++;

      if (delay == ECHO_FAILED) {
        this.status.delay = -1;
        this.message = "";
        this.classStyle = "red flash";
        this.windowClass = "red";
        this.status.description = connectionStatusUnmeasurable;

        return;
      }

      let avgDelay = Math.round(delayPerInterval / delaySamples);

      this.message = Number(avgDelay).toLocaleString() + "ms";
      this.status.delay = avgDelay;

      if (avgDelay < 30) {
        this.classStyle = "green";
        this.windowClass = "green";
        this.status.description =
          connectionStatusConnected + "。" + connectionDelayGood;
      } else if (avgDelay < 100) {
        this.classStyle = "yellow";
        this.windowClass = "yellow";
        this.status.description =
          connectionStatusConnected + "。" + connectionDelayFair;
      } else if (avgDelay < 300) {
        this.classStyle = "orange";
        this.windowClass = "orange";
        this.status.description =
          connectionStatusConnected + "。" + connectionDelayMedian;
      } else {
        this.classStyle = "red";
        this.windowClass = "red";
        this.status.description =
          connectionStatusConnected + "。" + connectionDelayHeavy;
      }
    },
    close(e) {
      isClosed = true;
      delayHistory.expire();
      inboundHistory.expire();
      outboundHistory.expire();

      ctx.connector.inputting = false;

      if (e === null) {
        this.message = "";
        this.classStyle = "";
        this.status.description = connectionStatusDisconnected;

        return;
      }

      this.status.delay = -1;
      this.message = "ERR";
      this.classStyle = "red flash";
      this.windowClass = "red";
      this.status.description = connectionStatusDisconnected + ": " + e;
    },
    failed(e) {
      isClosed = true;

      ctx.connector.inputting = false;

      if (e.code) {
        this.message = "E" + e.code;
      } else {
        this.message = "E????";
      }

      this.status.delay = -1;
      this.classStyle = "red flash";
      this.windowClass = "red";
      this.status.description = connectionStatusDisconnected + ". Error: " + e;
    },
  };
}
