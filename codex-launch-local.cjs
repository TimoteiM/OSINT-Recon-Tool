const net = require("node:net");

const originalListen = net.Server.prototype.listen;

net.Server.prototype.listen = function patchedListen(...args) {
  if (args[0] && typeof args[0] === "object") {
    args[0] = { ...args[0] };
    delete args[0].reusePort;
    if (args[0].host === "0.0.0.0") {
      args[0].host = "127.0.0.1";
    }
  }

  return originalListen.apply(this, args);
};

require("./dist/index.cjs");
