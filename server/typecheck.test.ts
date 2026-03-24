import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);

test("the project typechecks successfully", async () => {
  const command =
    process.platform === "win32"
      ? { file: "cmd.exe", args: ["/d", "/s", "/c", "node_modules\\.bin\\tsc.cmd --pretty false"] }
      : { file: "node_modules/.bin/tsc", args: ["--pretty", "false"] };

  await assert.doesNotReject(async () => {
    await execFileAsync(command.file, command.args, {
      cwd: process.cwd(),
      env: process.env,
    });
  });
});
