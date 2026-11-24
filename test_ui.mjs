import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const browserCandidates = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  path.join(process.env.LOCALAPPDATA || '', 'Google\\Chrome\\Application\\chrome.exe'),
  path.join(process.env.LOCALAPPDATA || '', 'Microsoft\\Edge\\Application\\msedge.exe'),
];

const state = {
  proxy: {
    enabled: true,
    host: '127.0.0.1',
    port: 5038,
    listen_port: 10086,
    rules_file: 'rules.yaml',
    bypass: ['localhost', '127.0.0.1'],
  },
  proxy_online: true,
  proxy_url: 'http://127.0.0.1:10086',
  proxy_latency_ms: 12,
  proxy_upstream_online: true,
  proxy_upstream_url: 'http://127.0.0.1:5038',
  router_enabled: true,
  routing_rules_error: '',
  routing_rules_file: 'rules.yaml',
  proxy_upstream_latency_ms: 8,
  proxy_events: [
    { time: '14:02:11', host: 'www.xiaohongshu.com', action: 'PROXY', ok: true, rule: 'DOMAIN-SUFFIX,xiaohongshu.com,PROXY' },
    { time: '14:02:09', host: 'www.baidu.com', action: 'DIRECT', ok: true, rule: 'DOMAIN-SUFFIX,baidu.com,DIRECT' },
    { time: '14:01:58', host: 'example.com', action: 'ERROR', ok: false, error: '无法建立代理隧道' },
  ],
  adb_path: 'C:\\fake\\adb.exe',
  apps: [{
    id: 'sample-app',
    name: '示例应用',
    exe: 'C:\\Apps\\Example\\app.exe',
    args: '',
    kind: 'electron',
    effective_kind: 'electron',
    exists: true,
    resolved_exe: 'C:\\Apps\\Example\\app.exe',
    running: false,
    profile_running: false,
    note: '用于界面布局验证',
    bypass: [],
    detected_kind: 'electron',
    evidence: ['package.json'],
  }, {
    id: 'sample-app-no-note',
    name: '无备注应用',
    exe: 'C:\\Apps\\Other\\other.exe',
    args: '',
    kind: 'electron',
    effective_kind: 'electron',
    exists: true,
    resolved_exe: 'C:\\Apps\\Other\\other.exe',
    running: false,
    profile_running: false,
    note: '',
    bypass: [],
    detected_kind: 'electron',
    evidence: ['package.json'],
  }],
};

const adbState = {
  adb_found: true,
  adb_path: 'C:\\fake\\adb.exe',
  devices: [{ serial: 'SERIAL123', model: 'Test Phone', state: 'device' }],
  forwards: [{ serial: 'SERIAL123', local: 'tcp:5038', remote: 'tcp:5038' }],
  upstream_port: 5038,
  error: '',
};

function findBrowser() {
  const browser = process.env.DROIDBRIDGE_TEST_BROWSER || browserCandidates.find((candidate) => candidate && requireExists(candidate));
  assert.ok(browser, 'Chrome or Edge is required for UI tests');
  return browser;
}

function requireExists(filePath) {
  return existsSync(filePath);
}

async function startServer() {
  const html = await readFile(path.join(root, 'index.html'), 'utf8');
  const requests = [];
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    if (url.pathname === '/' || url.pathname === '/index.html') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(html);
      return;
    }
    if (url.pathname === '/api/state') {
      res.end(JSON.stringify(state));
      return;
    }
    if (url.pathname === '/api/adb/state') {
      res.end(JSON.stringify(adbState));
      return;
    }
    if (url.pathname === '/api/settings') {
      let body = '';
      for await (const chunk of req) body += chunk;
      requests.push({ path: url.pathname, body: body ? JSON.parse(body) : {} });
      res.end(JSON.stringify({ ok: true, state }));
      return;
    }
    if (url.pathname === '/api/app/delete' || url.pathname === '/api/app/add') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const parsed = body ? JSON.parse(body) : {};
      requests.push({ path: url.pathname, body: parsed });
      if (url.pathname === '/api/app/delete') {
        state.apps = state.apps.filter((app) => app.id !== parsed.id);
      } else {
        state.apps.push({
          id: parsed.id || `app_${Date.now()}`,
          name: parsed.name || '未命名应用',
          exe: parsed.exe || '',
          args: parsed.args || '',
          kind: parsed.kind || 'auto',
          effective_kind: parsed.kind === 'auto' ? 'generic' : (parsed.kind || 'generic'),
          note: parsed.note || '',
          bypass: [],
          exists: true,
          resolved_exe: parsed.exe || '',
          running: false,
          profile_running: false,
          detected_kind: 'generic',
          evidence: [],
        });
      }
      res.end(JSON.stringify({ ok: true, removed: 1, state }));
      return;
    }
    if (url.pathname === '/api/quit') {
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ error: 'not found' }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, requests, url: `http://127.0.0.1:${server.address().port}` };
}

async function startBrowser(browser) {
  const profile = await mkdtemp(path.join(os.tmpdir(), 'droidbridge-ui-'));
  const child = spawn(browser, [
    '--headless=new',
    '--disable-gpu',
    '--disable-extensions',
    '--no-first-run',
    '--no-default-browser-check',
    '--no-sandbox',
    '--remote-debugging-port=0',
    `--user-data-dir=${profile}`,
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });

  const wsUrl = await new Promise((resolve, reject) => {
    let stderr = '';
    const timer = setTimeout(() => reject(new Error(`Timed out waiting for DevTools: ${stderr}`)), 10000);
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
      const match = stderr.match(/DevTools listening on (ws:\/\/\S+)/);
      if (match) {
        clearTimeout(timer);
        resolve(match[1]);
      }
    });
    child.once('error', reject);
    child.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Browser exited before DevTools was ready: ${code}\n${stderr}`));
    });
  });

  const httpUrl = wsUrl.replace(/^ws:/, 'http:').replace(/\/devtools\/browser\/.*$/, '');
  const target = await fetch(`${httpUrl}/json/new?about:blank`, { method: 'PUT' }).then((response) => response.json());
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });

  let nextId = 1;
  const pending = new Map();
  const runtimeErrors = [];
  socket.addEventListener('message', (event) => {
    const message = JSON.parse(event.data);
    if (message.method === 'Runtime.exceptionThrown') {
      runtimeErrors.push(message.params.exceptionDetails.exception?.description || message.params.exceptionDetails.text);
    }
    if (message.method === 'Runtime.consoleAPICalled' && message.params.type === 'error') {
      runtimeErrors.push(message.params.args.map((arg) => arg.value || arg.description || '').join(' '));
    }
    if (!message.id) return;
    const handler = pending.get(message.id);
    if (!handler) return;
    pending.delete(message.id);
    if (message.error) handler.reject(new Error(`${message.error.message} (${message.error.code})`));
    else handler.resolve(message.result);
  });

  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });

  const evaluate = async (expression) => {
    const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    }
    return result.result.value;
  };

  const waitFor = async (expression, timeout = 5000) => {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      if (await evaluate(expression)) return;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`Timed out waiting for: ${expression}`);
  };

  await send('Page.enable');
  await send('Runtime.enable');
  return {
    child,
    profile,
    socket,
    send,
    evaluate,
    waitFor,
    runtimeErrors,
    async close() {
      try { socket.close(); } catch {}
      child.kill();
      await new Promise((resolve) => child.once('exit', resolve));
      await rm(profile, { recursive: true, force: true });
    },
  };
}

test('DroidBridge dashboard keeps ADB settings independent from proxy settings', { timeout: 30000 }, async (t) => {
  const { server, requests, url } = await startServer();
  const browser = await startBrowser(findBrowser());
  t.after(async () => {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  });

  await browser.send('Emulation.setDeviceMetricsOverride', { width: 1120, height: 780, deviceScaleFactor: 1, mobile: false });
  await browser.send('Page.navigate', { url });
  await browser.waitFor("document.readyState === 'complete'");
  await browser.waitFor("document.querySelector('#adbPath')?.textContent.includes('fake')");

  await t.test('renders a main workspace beside a status rail', async () => {
    assert.equal(await browser.evaluate("!!document.querySelector('#dashboard #appWorkspace')"), true);
    assert.equal(await browser.evaluate("!!document.querySelector('#dashboard #statusRail')"), true);
  });

  await t.test('aligns card actions when only one card has a note', async () => {
    const aligned = await browser.evaluate(`(() => {
      const cards = [...document.querySelectorAll('.card')];
      const first = cards.find(card => card.querySelector('.card-note'));
      const second = cards.find(card => !card.querySelector('.card-note'));
      const firstActions = first.querySelector('.card-actions').getBoundingClientRect();
      const secondActions = second.querySelector('.card-actions').getBoundingClientRect();
      return Math.abs(firstActions.top - secondActions.top) < 1;
    })()`);
    assert.equal(aligned, true);
  });

  await t.test('keeps secondary card actions on one row', async () => {
    const sameRow = await browser.evaluate(`(() => {
      const preview = document.querySelector('.card [data-act="preview"]');
      const remove = document.querySelector('.card [data-act="del"]');
      return Math.abs(preview.getBoundingClientRect().top - remove.getBoundingClientRect().top) < 1;
    })()`);
    assert.equal(sameRow, true);
  });

  await t.test('owns the adb path field inside the ADB panel', async () => {
    assert.equal(await browser.evaluate("!!document.querySelector('#adbPanel #sAdbPath')"), true);
    assert.equal(await browser.evaluate("!!document.querySelector('#settings #sAdbPath')"), false);
  });

  await t.test('aligns the proxy settings switch with its label', async () => {
    await browser.evaluate("document.querySelector('#btnSettings').click()");
    await browser.waitFor("document.querySelector('#settings').hidden === false");
    const layout = await browser.evaluate(`(() => {
      const label = document.querySelector('#settings label.switch');
      const input = label.querySelector('input');
      const text = label.querySelector('span');
      const labelStyle = getComputedStyle(label);
      const inputStyle = getComputedStyle(input);
      const inputRect = input.getBoundingClientRect();
      const textRect = text.getBoundingClientRect();
      return {
        display: labelStyle.display,
        alignItems: labelStyle.alignItems,
        width: inputStyle.width,
        height: inputStyle.height,
        marginTop: inputStyle.marginTop,
        padding: inputStyle.padding,
        centerDelta: Math.abs((inputRect.top + inputRect.height / 2) - (textRect.top + textRect.height / 2)),
      };
    })()`);
    assert.equal(layout.display, 'flex');
    assert.equal(layout.alignItems, 'center');
    assert.equal(layout.width, '16px');
    assert.equal(layout.height, '16px');
    assert.equal(layout.marginTop, '0px');
    assert.equal(layout.padding, '0px');
    assert.ok(layout.centerDelta < 1, `checkbox and label centers differ by ${layout.centerDelta}px`);
    if (process.env.DROIDBRIDGE_UI_SCREENSHOT) {
      const screenshot = await browser.send('Page.captureScreenshot', { format: 'png' });
      await writeFile(process.env.DROIDBRIDGE_UI_SCREENSHOT, Buffer.from(screenshot.data, 'base64'));
    }
    await browser.evaluate("document.querySelector('#btnSettingsCancel').click()");
  });

  await t.test('proxy settings save without adb configuration', async () => {
    await browser.evaluate("document.querySelector('#btnSettings').click()");
    await browser.waitFor("document.querySelector('#settings').hidden === false");
    await browser.evaluate("document.querySelector('#btnSettingsSave').click()");
    const deadline = Date.now() + 5000;
    let saved;
    while (Date.now() < deadline) {
      saved = requests.findLast((request) => request.path === '/api/settings');
      if (saved) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(saved, 'proxy settings request was sent');
    assert.equal(Object.hasOwn(saved.body, 'adb_path'), false);
  });

  await t.test('saves adb path independently from the ADB panel', async () => {
    await browser.evaluate("document.querySelector('#btnAdbSettings').click()");
    await browser.waitFor("document.querySelector('#adbSettings').hidden === false");
    await browser.evaluate(`document.querySelector('#sAdbPath').value = ${JSON.stringify('D:\\tools\\adb.exe')}`);
    await browser.evaluate("document.querySelector('#btnAdbSettingsSave').click()");
    const deadline = Date.now() + 5000;
    let saved;
    while (Date.now() < deadline) {
      saved = requests.findLast((request) => request.path === '/api/settings' && Object.hasOwn(request.body, 'adb_path'));
      if (saved) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(saved, 'ADB settings request was sent');
    assert.deepEqual(saved.body, { adb_path: 'D:\\tools\\adb.exe' });
  });

  assert.deepEqual(browser.runtimeErrors, []);
});

test('DroidBridge dashboard live chain, search, routing feed and undo', { timeout: 60000 }, async (t) => {
  const { server, url } = await startServer();
  const browser = await startBrowser(findBrowser());
  t.after(async () => {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  });

  await browser.send('Emulation.setDeviceMetricsOverride', { width: 1120, height: 900, deviceScaleFactor: 1, mobile: false });
  await browser.send('Page.navigate', { url });
  await browser.waitFor("document.readyState === 'complete'");
  await browser.waitFor("document.querySelectorAll('#appGrid .card').length === 2");

  await t.test('renders a four-hop live chain with statuses', async () => {
    if (process.env.DROIDBRIDGE_UI_SHOT_DESKTOP) {
      const shot = await browser.send('Page.captureScreenshot', { format: 'png' });
      await writeFile(process.env.DROIDBRIDGE_UI_SHOT_DESKTOP, Buffer.from(shot.data, 'base64'));
    }
    const chain = await browser.evaluate(`(() => ({
      hops: document.querySelectorAll('#chain li.hop').length,
      entry: document.querySelector('#hopEntryState').textContent,
      clash: document.querySelector('#hopClashState').textContent,
      badge: document.querySelector('#chainBadge').textContent,
      entryFlow: document.querySelector('#hopEntry').classList.contains('flow'),
    }))()`);
    assert.equal(chain.hops, 4);
    assert.equal(chain.entry, '12ms');
    assert.equal(chain.clash, '8ms');
    assert.equal(chain.badge, '畅通');
    assert.equal(chain.entryFlow, true);
  });

  await t.test('draws the latency sparkline from samples', async () => {
    const spark = await browser.evaluate(`(() => {
      LATENCY_HISTORY.length = 0;
      LATENCY_HISTORY.push(14, 9, 18, 11);
      renderSpark();
      return {
        line: document.querySelector('#sparkLine').getAttribute('d').length > 10,
        area: document.querySelector('#sparkArea').getAttribute('d').length > 10,
        now: document.querySelector('#sparkNow').textContent,
        min: document.querySelector('#sparkMin').textContent,
      };
    })()`);
    assert.equal(spark.line, true);
    assert.equal(spark.area, true);
    assert.equal(spark.now, '11ms');
    assert.equal(spark.min, '最低 9ms');
  });

  await t.test('search filters cards live and clears', async () => {
    await browser.evaluate(`(() => {
      const input = document.querySelector('#appSearch');
      input.value = '无备注';
      input.dispatchEvent(new Event('input', { bubbles: true }));
    })()`);
    assert.equal(await browser.evaluate("document.querySelectorAll('#appGrid .card').length"), 1);
    assert.equal(await browser.evaluate("document.querySelector('#appGrid .card .card-name').textContent"), '无备注应用');
    await browser.evaluate("document.querySelector('#btnSearchClear').click()");
    assert.equal(await browser.evaluate("document.querySelectorAll('#appGrid .card').length"), 2);
  });

  await t.test('issue filter shows a recoverable empty state', async () => {
    await browser.evaluate("document.querySelector('#appChips [data-filter=\"issue\"]').click()");
    assert.equal(await browser.evaluate("document.querySelectorAll('#appGrid .card').length"), 0);
    assert.equal(await browser.evaluate("!!document.querySelector('#btnClearFilters')"), true);
    await browser.evaluate("document.querySelector('#btnClearFilters').click()");
    assert.equal(await browser.evaluate("document.querySelectorAll('#appGrid .card').length"), 2);
  });

  await t.test('routing feed lists decisions and filters by action', async () => {
    assert.equal(await browser.evaluate("document.querySelectorAll('#eventsBody .event-row').length"), 3);
    await browser.evaluate("document.querySelector('#eventChips [data-efilter=\"DIRECT\"]').click()");
    const rows = await browser.evaluate(`(() => ({
      count: document.querySelectorAll('#eventsBody .event-row').length,
      host: document.querySelector('#eventsBody .event-host .h').textContent,
      badge: document.querySelector('#eventsBody .badge').textContent,
    }))()`);
    assert.equal(rows.count, 1);
    assert.equal(rows.host, 'www.baidu.com');
    assert.equal(rows.badge, '直连');
    await browser.evaluate("document.querySelector('#eventChips [data-efilter=\"all\"]').click()");
  });

  await t.test('delete asks in-app and undo restores the app', async () => {
    await browser.evaluate("document.querySelector('#appGrid .card [data-act=\"del\"]').click()");
    await browser.waitFor("document.querySelector('#confirm').hidden === false");
    assert.equal(await browser.evaluate("document.querySelector('#confirmTitle').textContent"), '移除应用');
    await browser.evaluate("document.querySelector('#confirmOk').click()");
    await browser.waitFor("document.querySelectorAll('#appGrid .card').length === 1");
    await browser.waitFor("!!document.querySelector('#toast button')");
    assert.equal(await browser.evaluate("document.querySelector('#toast button').textContent"), '撤销');
    await browser.evaluate("document.querySelector('#toast button').click()");
    await browser.waitFor("document.querySelectorAll('#appGrid .card').length === 2");
  });

  await t.test('escape closes the editor', async () => {
    await browser.evaluate("document.querySelector('#btnAdd').click()");
    await browser.waitFor("document.querySelector('#editor').hidden === false");
    await browser.evaluate("document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))");
    assert.equal(await browser.evaluate("document.querySelector('#editor').hidden"), true);
  });

  await t.test('log level filter and long-line wrapping', async () => {
    const wrap = await browser.evaluate(`(() => {
      log('X'.repeat(400), 'dim');
      const msg = document.querySelector('#logList .log-row .log-msg');
      const style = getComputedStyle(msg);
      return { wordBreak: style.wordBreak, whiteSpace: style.whiteSpace, overflows: msg.scrollWidth > msg.clientWidth + 1 };
    })()`);
    assert.equal(wrap.wordBreak, 'break-word');
    assert.equal(wrap.overflows, false);
    await browser.evaluate("document.querySelector('#logChips [data-lfilter=\"err\"]').click()");
    assert.equal(await browser.evaluate("document.querySelectorAll('#logList .log-row.err').length"), 0);
    await browser.evaluate("document.querySelector('#logChips [data-lfilter=\"all\"]').click()");
  });

  await t.test('mobile layout has no horizontal overflow', async () => {
    await browser.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const layout = await browser.evaluate(`(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      innerWidth: window.innerWidth,
      chainVisible: !!document.querySelector('#chainPanel').offsetHeight,
      addVisible: !!document.querySelector('#btnAdd').offsetHeight,
      toggleVisible: !!document.querySelector('#proxyEnabled').offsetHeight,
      railBelow: document.querySelector('#statusRail').getBoundingClientRect().top > document.querySelector('#appGrid').getBoundingClientRect().bottom - 1,
      singleColCards: (() => { const c = [...document.querySelectorAll('#appGrid .card')]; return c.length < 2 || Math.abs(c[0].getBoundingClientRect().top - c[1].getBoundingClientRect().top) > 1; })(),
    }))()`);
    assert.equal(layout.innerWidth, 390);
    assert.equal(layout.railBelow, true);
    assert.equal(layout.singleColCards, true);
    assert.ok(layout.scrollWidth <= layout.innerWidth + 1, `horizontal overflow: ${layout.scrollWidth} > ${layout.innerWidth}`);
    assert.equal(layout.chainVisible, true);
    assert.equal(layout.addVisible, true);
    assert.equal(layout.toggleVisible, true);
    if (process.env.DROIDBRIDGE_UI_SHOT_MOBILE) {
      const shot = await browser.send('Page.captureScreenshot', { format: 'png' });
      await writeFile(process.env.DROIDBRIDGE_UI_SHOT_MOBILE, Buffer.from(shot.data, 'base64'));
    }
  });

  assert.deepEqual(browser.runtimeErrors, []);
});
