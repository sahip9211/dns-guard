import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = fileURLToPath(new URL("../../", import.meta.url));
const binary = process.env.DNS_GUARD_TEST_BINARY || resolve(root, "target/debug/dns-guard");
const delay = (ms) => new Promise((done) => setTimeout(done, ms));

test("dashboard authenticates, renders real counters, pauses, reconnects and forgets credentials", {timeout: 35000}, async () => {
  const dir = mkdtempSync(resolve(tmpdir(), "dns-guard-web-"));
  let child, browser;
  try {
    const cli = (...args) => execFileSync(binary, args, {cwd: dir, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8"}).trim();
    writeFileSync(resolve(dir, "fixture.txt"), "blocked.example\n");
    cli("compile", "rules.dngi", "--other-bytes", "1000000", "--feed", "domains", "ads", "fixture.txt");
    const token = cli("management", "token-create", "api.key");
    child = spawn(binary, ["serve", "rules.dngi", "--listen", "127.0.0.1:0", "--upstream", "192.0.2.1:53", "--management-listen", "127.0.0.1:0", "--management-token-file", "api.key"], {cwd:dir, stdio:["ignore","ignore","pipe"]});
    const url = await new Promise((done, fail) => {
      const timeout = setTimeout(() => fail(new Error("service startup timeout")), 8000);
      let log = "";
      child.stderr.on("data", (chunk) => {
        log += chunk.toString();
        assert.ok(!log.includes(token), "startup must not log token");
        const match = log.match(/Management listening on (http:\/\/[^\s]+)/);
        if (match) { clearTimeout(timeout); done(match[1]); }
      });
      child.once("exit", () => { clearTimeout(timeout); fail(new Error("service exited during startup")); });
    });
    browser = await chromium.launch({headless:true, ...(process.env.DNS_GUARD_CHROMIUM ? {executablePath:process.env.DNS_GUARD_CHROMIUM} : {})});
    const page = await browser.newPage({viewport:{width:1200,height:900}});
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    let polls = 0;
    page.on("request", (request) => { if (request.url().endsWith("/api/v1/status")) polls++; });
    await page.goto(url);
    assert.equal(await page.locator("#overview").isVisible(), false);
    await page.getByLabel("Read-only access token").fill("0".repeat(64));
    await page.getByRole("button", {name:"Connect",exact:true}).click();
    await page.getByRole("status").filter({hasText:"Token rejected"}).waitFor();
    await page.getByLabel("Read-only access token").fill(token);
    await page.getByRole("button", {name:"Connect",exact:true}).click();
    await page.locator("#overview").waitFor({state:"visible"});
    assert.equal(await page.locator(".metric").count(), 6);
    assert.equal(await page.locator(".metric strong").first().textContent(), "0");
    assert.ok((await page.locator("#service-meta").textContent()).includes("1 rule"));
    assert.equal(await page.locator("#token").inputValue(), "");
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    assert.deepEqual(await page.context().cookies(), []);
    await page.evaluate(() => {
      Object.defineProperty(document, "hidden", {configurable:true, value:true});
      document.dispatchEvent(new Event("visibilitychange"));
    });
    const paused = polls;
    await delay(2400);
    assert.equal(polls, paused, "hidden tabs must not poll");
    await page.evaluate(() => {
      Object.defineProperty(document, "hidden", {configurable:true, value:false});
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await page.getByRole("status").filter({hasText:"Connected"}).waitFor();
    assert.ok(polls > paused);
    await page.route("**/api/v1/status", route => route.abort());
    await page.getByRole("status").filter({hasText:"Service unavailable"}).waitFor();
    await page.unroute("**/api/v1/status");
    await page.getByRole("status").filter({hasText:"Connected"}).waitFor();
    await page.setViewportSize({width:375,height:812});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    if (process.env.DNS_GUARD_SCREENSHOT) {
      mkdirSync(resolve(root, "results/web"), {recursive:true});
      await page.screenshot({path:resolve(root, "results/web/dashboard.png"), fullPage:true});
    }
    await page.getByRole("button", {name:"Disconnect"}).click();
    assert.equal(await page.locator("#overview").isVisible(), false);
    const stopped = polls;
    await delay(2400);
    assert.equal(polls, stopped);
    await page.reload();
    assert.equal(await page.locator("#token").inputValue(), "");
    assert.equal(await page.locator("#overview").isVisible(), false);
    assert.deepEqual(errors, []);
  } finally {
    await browser?.close();
    if (child && child.exitCode === null) {
      const exited = new Promise(done => child.once("exit", done));
      child.kill("SIGTERM"); await exited;
    }
    rmSync(dir, {recursive:true,force:true});
  }
});
