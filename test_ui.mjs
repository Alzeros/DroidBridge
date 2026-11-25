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
  },
  proxy_online: true,
  proxy_url: 'http://127.0.0.1:10086',
  proxy_latency_ms: 12,
  proxy_upstream_online: true,
  proxy_upstream_url: 'http://127.0.0.1:5038',
  routing_rules_error: '',
  routing_rules_file: 'rules.yaml',
  proxy_upstream_latency_ms: 8,
  tray_active: false,
  adb_serial: '',
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
    running: true,
    profile_running: false,
    note: '用于界面布局验证',
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
  const iconSvg = await readFile(path.join(root, 'droidbridge.svg'));
  const iconPng = await readFile(path.join(root, 'droidbridge.png'));
  const iconIco = await readFile(path.join(root, 'droidbridge.ico'));
  const requests = [];
  let rulesText = 'rules:\n  - DOMAIN-SUFFIX,baidu.com,DIRECT\n  - MATCH,PROXY\n';
  let exitIpCalls = 0;
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    if (url.pathname === '/' || url.pathname === '/index.html') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(html);
      return;
    }
    if (url.pathname === '/icon.svg') {
      res.setHeader('Content-Type', 'image/svg+xml; charset=utf-8');
      res.end(iconSvg);
      return;
    }
    if (url.pathname === '/icon.png') {
      res.setHeader('Content-Type', 'image/png');
      res.end(iconPng);
      return;
    }
    if (url.pathname === '/favicon.ico') {
      res.setHeader('Content-Type', 'image/x-icon');
      res.end(iconIco);
      return;
    }
    if (url.pathname === '/api/state') {
      requests.push({ path: url.pathname });
      res.end(JSON.stringify(state));
      return;
    }
    if (url.pathname === '/api/adb/state') {
      res.end(JSON.stringify(adbState));
      return;
    }
    if (url.pathname === '/api/exit-ip') {
      exitIpCalls += 1;
      requests.push({ path: url.pathname, call: exitIpCalls });
      const first = exitIpCalls === 1;
      res.end(JSON.stringify({
        ok: true,
        ip: first ? '203.0.113.42' : '198.51.100.77',
        country_code: first ? 'JP' : 'SG',
        country: first ? 'Japan' : 'Singapore',
        region: first ? 'Tokyo' : '',
        city: first ? 'Tokyo' : 'Singapore',
        location: first ? 'Japan, Tokyo' : 'Singapore',
        isp: first ? 'HYW' : 'Cloudflare',
        asn: first ? 11421 : 13335,
        timezone: first ? 'Asia/Tokyo' : 'Asia/Singapore',
        error: '',
        source: 'https://api.ip.sb/geoip',
        via: 'http://127.0.0.1:5038',
        latency_ms: first ? 185 : 142,
        checked_at: first ? '14:02:15' : '14:02:29',
      }));
      return;
    }
    if (url.pathname === '/api/adb/forward' || url.pathname === '/api/adb/unforward') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const parsed = body ? JSON.parse(body) : {};
      requests.push({ path: url.pathname, body: parsed });
      res.end(JSON.stringify({ ok: true, serial: parsed.serial || 'SERIAL123', local: 'tcp:5038', remote: 'tcp:5038' }));
      return;
    }
    if (url.pathname === '/api/rules' && req.method === 'GET') {
      res.end(JSON.stringify({ ok: true, path: 'rules.yaml', content: rulesText, error: '', rule_count: 2, upstream: 'http://127.0.0.1:5038' }));
      return;
    }
    if (url.pathname === '/api/rules' && req.method === 'POST') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const parsed = body ? JSON.parse(body) : {};
      requests.push({ path: url.pathname, body: parsed });
      if (!String(parsed.content || '').includes('MATCH,')) {
        res.statusCode = 400;
        res.end(JSON.stringify({ ok: false, error: 'rules 最后一条必须是 MATCH' }));
        return;
      }
      rulesText = parsed.content;
      res.end(JSON.stringify({ ok: true, path: 'rules.yaml', rule_count: 3, state }));
      return;
    }
    if (url.pathname === '/api/rules/test') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const parsed = body ? JSON.parse(body) : {};
      requests.push({ path: url.pathname, body: parsed });
      res.end(JSON.stringify({ ok: true, host: parsed.host, action: 'DIRECT', rule: 'DOMAIN-SUFFIX,baidu.com,DIRECT', rule_index: 1 }));
      return;
    }
    if (url.pathname === '/api/rules/quick-add') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const parsed = body ? JSON.parse(body) : {};
      requests.push({ path: url.pathname, body: parsed });
      res.end(JSON.stringify({ ok: true, rule: `DOMAIN,${parsed.host},${parsed.action}`, changed: true, message: `已添加规则：DOMAIN,${parsed.host},${parsed.action}`, state }));
      return;
    }
    if (url.pathname === '/api/events/clear') {
      requests.push({ path: url.pathname });
      const cleared = state.proxy_events.length;
      state.proxy_events = [];
      res.end(JSON.stringify({ ok: true, cleared, state }));
      return;
    }
    if (url.pathname === '/api/app/firefox/sync') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const parsed = body ? JSON.parse(body) : {};
      requests.push({ path: url.pathname, body: parsed });
      res.end(JSON.stringify({ ok: true, message: '已同步本机配置（含 3 个扩展）', state }));
      return;
    }
    if (url.pathname === '/api/app/firefox/open-profile') {
      res.end(JSON.stringify({ ok: true, path: 'S:\\Mydevelop\\DroidBridge\\profiles\\ff' }));
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

  await t.test('renders sidebar navigation, main workspace, and status rail', async () => {
    const shell = await browser.evaluate(`(() => ({
      navCount: document.querySelectorAll('#mainNav .nav-item').length,
      workspace: !!document.querySelector('#dashboard #appWorkspace'),
      statusRail: !!document.querySelector('#dashboard #statusRail'),
      railPanels: document.querySelectorAll('#statusRail > .panel').length,
      appsVisible: !document.querySelector('#viewApps').hidden,
      trafficHidden: document.querySelector('#viewTraffic').hidden,
      rulesHidden: document.querySelector('#viewRules').hidden,
      settingsHidden: document.querySelector('#viewSettings').hidden,
    }))()`);
    assert.deepEqual(shell, {
      navCount: 4,
      workspace: true,
      statusRail: true,
      railPanels: 1,
      appsVisible: true,
      trafficHidden: true,
      rulesHidden: true,
      settingsHidden: true,
    });
  });

  await t.test('stacks rows vertically and aligns right action columns when only one row has a note', async () => {
    const aligned = await browser.evaluate(`(() => {
      const cards = [...document.querySelectorAll('.card')];
      const first = cards.find(card => card.querySelector('.card-note'));
      const second = cards.find(card => !card.querySelector('.card-note'));
      const firstRect = first.getBoundingClientRect();
      const secondRect = second.getBoundingClientRect();
      const firstActions = first.querySelector('.card-actions').getBoundingClientRect();
      const secondActions = second.querySelector('.card-actions').getBoundingClientRect();
      const firstLaunch = first.querySelector('[data-act="launch"]').getBoundingClientRect();
      const secondLaunch = second.querySelector('[data-act="launch"]').getBoundingClientRect();
      return {
        stacked: secondRect.top >= firstRect.bottom - 1,
        actionsAligned: Math.abs(firstActions.right - secondActions.right) < 1,
        launchAligned: Math.abs(firstLaunch.right - secondLaunch.right) < 1,
      };
    })()`);
    assert.deepEqual(aligned, { stacked: true, actionsAligned: true, launchAligned: true });
  });

  await t.test('keeps secondary card actions quiet and on one row', async () => {
    const secondary = await browser.evaluate(`(() => {
      const preview = document.querySelector('.card [data-act="preview"]');
      const edit = document.querySelector('.card [data-act="edit"]');
      const remove = document.querySelector('.card [data-act="del"]');
      const row = preview.closest('.card-secondary').getBoundingClientRect();
      const previewRect = preview.getBoundingClientRect();
      const removeRect = remove.getBoundingClientRect();
      return {
        sameRow: Math.abs(previewRect.top - removeRect.top) < 1,
        previewLabel: preview.getAttribute('aria-label'),
        editLabel: edit.getAttribute('aria-label'),
        previewWidth: previewRect.width,
        previewHeight: previewRect.height,
        deleteWidth: removeRect.width,
        deleteHeight: removeRect.height,
        deleteRightGap: row.right - removeRect.right,
      };
    })()`);
    assert.equal(secondary.sameRow, true);
    assert.equal(secondary.previewLabel, '注入详情');
    assert.equal(secondary.editLabel, '编辑');
    assert.ok(secondary.previewWidth >= 32, `preview target width: ${secondary.previewWidth}px`);
    assert.ok(secondary.previewHeight >= 32, `preview target height: ${secondary.previewHeight}px`);
    assert.ok(secondary.deleteWidth >= 32, `delete target width: ${secondary.deleteWidth}px`);
    assert.ok(secondary.deleteHeight >= 32, `delete target height: ${secondary.deleteHeight}px`);
    assert.ok(secondary.deleteRightGap < 2, `delete action is not right-aligned: ${secondary.deleteRightGap}px`);
  });

  await t.test('owns the adb path field inside the ADB panel and separates proxy settings', async () => {
    await browser.evaluate("document.querySelector('#navSettings').click()");
    await browser.waitFor("document.querySelector('#viewSettings').hidden === false");
    const panels = await browser.evaluate(`(() => ({
      adbOwnsPath: !!document.querySelector('#adbPanel #sAdbPath'),
      proxyOwnsPath: !!document.querySelector('#proxyPanel #sAdbPath'),
      adbBadge: document.querySelector('#adbSummaryBadge')?.textContent,
      proxyBadge: document.querySelector('#proxyPanelBadge')?.textContent,
    }))()`);
    assert.equal(panels.adbOwnsPath, true);
    assert.equal(panels.proxyOwnsPath, false);
    assert.equal(panels.adbBadge, '已连接');
    assert.match(panels.proxyBadge, /^在线/);
  });

  await t.test('uses rules.yaml as the only routing source', async () => {
    await browser.evaluate("document.querySelector('#navSettings').click()");
    await browser.waitFor("document.querySelector('#viewSettings').hidden === false");
    const settings = await browser.evaluate(`(() => ({
      rulesFile: document.querySelector('#sRulesFile').value,
      help: document.querySelector('#proxyPanel .field-help').textContent.trim(),
      hasRouterToggle: !!document.querySelector('#sRouterEnabled'),
      hasGlobalBypass: !!document.querySelector('#sBypass'),
      hasAppBypass: !!document.querySelector('#fBypass'),
      hint: document.querySelector('#settingsHint').textContent,
    }))()`);
    assert.equal(settings.rulesFile, 'rules.yaml');
    assert.match(settings.help, /所有代理请求统一进入本地分流入口/);
    assert.equal(settings.hasRouterToggle, false);
    assert.equal(settings.hasGlobalBypass, false);
    assert.equal(settings.hasAppBypass, false);
    assert.match(settings.hint, /127\.0\.0\.1:10086/);
    if (process.env.DROIDBRIDGE_UI_SCREENSHOT) {
      const screenshot = await browser.send('Page.captureScreenshot', { format: 'png' });
      await writeFile(process.env.DROIDBRIDGE_UI_SCREENSHOT, Buffer.from(screenshot.data, 'base64'));
    }
  });

  await t.test('proxy settings save without adb configuration', async () => {
    await browser.evaluate("document.querySelector('#navSettings').click()");
    await browser.waitFor("document.querySelector('#viewSettings').hidden === false");
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
    assert.deepEqual(Object.keys(saved.body.proxy).sort(), [
      'enabled', 'host', 'listen_port', 'port', 'rules_file',
    ]);
  });

  await t.test('saves adb path independently from the ADB panel', async () => {
    await browser.evaluate("document.querySelector('#navSettings').click()");
    await browser.waitFor("document.querySelector('#viewSettings').hidden === false");
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
  const { server, requests, url } = await startServer();
  const browser = await startBrowser(findBrowser());
  t.after(async () => {
    await browser.close();
    await new Promise((resolve) => server.close(resolve));
  });

  await browser.send('Emulation.setDeviceMetricsOverride', { width: 1120, height: 780, deviceScaleFactor: 1, mobile: false });
  await browser.send('Page.navigate', { url });
  await browser.waitFor("document.readyState === 'complete'");
  await browser.waitFor("document.querySelectorAll('#appGrid .card').length === 2");

  await t.test('renders a four-hop live chain with statuses and supports keyboard 1-4 view switching', async () => {
    if (process.env.DROIDBRIDGE_UI_SHOT_DESKTOP) {
      const shot = await browser.send('Page.captureScreenshot', { format: 'png' });
      await writeFile(process.env.DROIDBRIDGE_UI_SHOT_DESKTOP, Buffer.from(shot.data, 'base64'));
    }
    const chain = await browser.evaluate(`(() => {
      const active = {
        hops: document.querySelectorAll('#chain li.hop').length,
        entry: document.querySelector('#hopEntryState').textContent,
        clash: document.querySelector('#hopClashState').textContent,
        badge: document.querySelector('#chainBadge').textContent,
        appsFlow: document.querySelector('#hopApps').classList.contains('flow'),
        entryFlow: document.querySelector('#hopEntry').classList.contains('flow'),
        clashFlow: document.querySelector('#hopClash').classList.contains('flow'),
      };
      const prevRunning = STATE.apps[0].running;
      STATE.apps[0].running = false;
      renderChain();
      const idleAppsFlow = document.querySelector('#hopApps').classList.contains('flow');
      const idleEntryFlow = document.querySelector('#hopEntry').classList.contains('flow');
      STATE.apps[0].running = prevRunning;
      const prevEnabled = STATE.proxy.enabled;
      STATE.proxy.enabled = false;
      renderChain();
      const disabledAppsFlow = document.querySelector('#hopApps').classList.contains('flow');
      STATE.proxy.enabled = prevEnabled;
      renderChain();
      return { ...active, idleAppsFlow, idleEntryFlow, disabledAppsFlow };
    })()`);
    assert.equal(chain.hops, 4);
    assert.equal(chain.entry, '12ms');
    assert.equal(chain.clash, '8ms');
    assert.equal(chain.badge, '畅通');
    assert.equal(chain.appsFlow, true);
    assert.equal(chain.entryFlow, true);
    assert.equal(chain.clashFlow, true);
    assert.equal(chain.idleAppsFlow, false);
    assert.equal(chain.idleEntryFlow, true);
    assert.equal(chain.disabledAppsFlow, false);

    await browser.evaluate("document.dispatchEvent(new KeyboardEvent('keydown', { key: '2', bubbles: true }))");
    assert.equal(await browser.evaluate("document.querySelector('#viewTraffic').hidden"), false);
    await browser.evaluate("document.dispatchEvent(new KeyboardEvent('keydown', { key: '1', bubbles: true }))");
    assert.equal(await browser.evaluate("document.querySelector('#viewApps').hidden"), false);
  });

  await t.test('loads exit IP, location, ISP/ASN from api.ip.sb and syncs both rail and sidebar dock on refresh', async () => {
    await browser.waitFor("document.querySelector('#exitIpVal')?.textContent === '203.0.113.42'");
    const initial = await browser.evaluate(`(() => ({
      val: document.querySelector('#exitIpVal').textContent,
      dockVal: document.querySelector('#dockExitIp').textContent,
      disabled: document.querySelector('#exitIpVal').disabled,
      cc: document.querySelector('#exitIpCountryCode').textContent,
      ccHidden: document.querySelector('#exitIpCountryCode').hidden,
      loc: document.querySelector('#exitIpLoc').textContent,
      isp: document.querySelector('#exitIpIsp').textContent,
      meta: document.querySelector('#exitIpMeta').textContent,
    }))()`);
    assert.equal(initial.val, '203.0.113.42');
    assert.equal(initial.dockVal, '203.0.113.42');
    assert.equal(initial.disabled, false);
    assert.equal(initial.cc, 'JP');
    assert.equal(initial.ccHidden, false);
    assert.equal(initial.loc, 'Japan, Tokyo');
    assert.equal(initial.isp, 'HYW · AS11421');
    assert.match(initial.meta, /api\.ip\.sb/);
    assert.match(initial.meta, /14:02:15/);

    await browser.evaluate("document.querySelector('#btnRefreshExitIp').click()");
    await browser.waitFor("document.querySelector('#exitIpVal')?.textContent === '198.51.100.77'");
    const refreshed = await browser.evaluate(`(() => ({
      val: document.querySelector('#exitIpVal').textContent,
      dockVal: document.querySelector('#dockExitIp').textContent,
      cc: document.querySelector('#exitIpCountryCode').textContent,
      loc: document.querySelector('#exitIpLoc').textContent,
      isp: document.querySelector('#exitIpIsp').textContent,
      meta: document.querySelector('#exitIpMeta').textContent,
    }))()`);
    assert.equal(refreshed.val, '198.51.100.77');
    assert.equal(refreshed.dockVal, '198.51.100.77');
    assert.equal(refreshed.cc, 'SG');
    assert.equal(refreshed.loc, 'Singapore');
    assert.equal(refreshed.isp, 'Cloudflare · AS13335');
    assert.match(refreshed.meta, /14:02:29/);
    assert.equal(requests.filter((r) => r.path === '/api/exit-ip').length, 2);
  });

  await t.test('labels native Chromium browsers without a marker count', async () => {
    const nativeBrowser = await browser.evaluate(`(() => {
      const sampleCard = document.querySelector('.card[data-id="sample-app"]');
      const sampleRunning = sampleCard.querySelector('.status-pill.running')?.textContent?.trim() || '';
      const app = {
        ...STATE.apps[0],
        id: 'chrome-preview',
        name: 'Chrome',
        kind: 'auto',
        detected_kind: 'electron',
        effective_kind: 'electron',
        native_browser: true,
        running: false,
        evidence: ['browser binary'],
      };
      const invalidApp = {
        ...STATE.apps[1],
        id: 'invalid-preview',
        name: '失效应用',
        exists: false,
        running: false,
      };
      STATE.apps.push(app, invalidApp);
      renderGrid();
      const card = document.querySelector('.card[data-id="chrome-preview"]');
      const tagEl = card.querySelector('.stack-tag');
      const tagText = tagEl?.textContent?.trim() || '';
      const tagTitle = tagEl?.getAttribute('title') || '';
      const visibleText = card.textContent.replace(/\\s+/g, ' ').trim();
      const invalidCard = document.querySelector('.card[data-id="invalid-preview"]');
      const invalidStatus = invalidCard.querySelector('.status-pill.bad')?.textContent?.trim() || '';
      const invalidLaunchDisabled = !!invalidCard.querySelector('[data-act="launch"]')?.disabled;
      STATE.apps = STATE.apps.filter((item) => item.id !== 'chrome-preview' && item.id !== 'invalid-preview');
      renderGrid();
      return {
        sampleRunning,
        tagText,
        tagTitle,
        visibleText,
        invalidStatus,
        invalidLaunchDisabled,
        count: document.querySelectorAll('#appGrid .card').length,
      };
    })()`);
    assert.equal(nativeBrowser.sampleRunning, '运行中');
    assert.equal(nativeBrowser.tagText, 'Chromium');
    assert.match(nativeBrowser.tagTitle, /原生 Chromium 浏览器/);
    assert.doesNotMatch(nativeBrowser.tagTitle, /项特征/);
    assert.doesNotMatch(nativeBrowser.visibleText, /文件存在/);
    assert.doesNotMatch(nativeBrowser.visibleText, /项特征/);
    assert.equal(nativeBrowser.invalidStatus, '路径失效');
    assert.equal(nativeBrowser.invalidLaunchDisabled, true);
    assert.equal(nativeBrowser.count, 2);
  });

  await t.test('draws the latency sparkline from upstream samples', async () => {
    const initialHistory = await browser.evaluate('LATENCY_HISTORY.slice()');
    assert.deepEqual(initialHistory, [8]);
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

  await t.test('traffic view defaults to routing, switches to logs, searches, renders >40 rows, quick-adds and clears', async () => {
    await browser.evaluate("document.querySelector('#btnJumpTraffic').click()");
    await browser.waitFor("document.querySelector('#viewTraffic').hidden === false");
    if (process.env.DROIDBRIDGE_UI_SHOT_TRAFFIC) {
      const shot = await browser.send('Page.captureScreenshot', { format: 'png' });
      await writeFile(process.env.DROIDBRIDGE_UI_SHOT_TRAFFIC, Buffer.from(shot.data, 'base64'));
    }

    const initial = await browser.evaluate(`(() => ({
      eventsTabActive: document.querySelector('#tabEvents').classList.contains('active'),
      eventsVisible: !document.querySelector('#eventsBody').hidden,
      logsHidden: document.querySelector('#logPanel').hidden,
      eventToolsVisible: !document.querySelector('#eventChips').hidden,
      logToolsHidden: document.querySelector('#logTools').hidden,
    }))()`);
    assert.deepEqual(initial, {
      eventsTabActive: true,
      eventsVisible: true,
      logsHidden: true,
      eventToolsVisible: true,
      logToolsHidden: true,
    });

    await browser.evaluate("document.querySelector('#tabLogs').click()");
    const logs = await browser.evaluate(`(() => ({
      logsVisible: !document.querySelector('#logPanel').hidden,
      eventsHidden: document.querySelector('#eventsBody').hidden,
      eventToolsHidden: document.querySelector('#eventChips').hidden,
      logToolsVisible: !document.querySelector('#logTools').hidden,
      selected: document.querySelector('#tabLogs').getAttribute('aria-selected'),
    }))()`);
    assert.deepEqual(logs, {
      logsVisible: true,
      eventsHidden: true,
      eventToolsHidden: true,
      logToolsVisible: true,
      selected: 'true',
    });

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

    await browser.evaluate("document.querySelector('#tabEvents').click()");
    assert.equal(await browser.evaluate("document.querySelector('#logPanel').hidden"), true);
    assert.equal(await browser.evaluate("document.querySelectorAll('#eventsBody .event-row').length"), 3);

    await browser.evaluate("document.querySelector('#eventChips [data-efilter=\"DIRECT\"]').click()");
    const rows = await browser.evaluate(`(() => ({
      count: document.querySelectorAll('#eventsBody .event-row').length,
      host: document.querySelector('#eventsBody .event-host .h').textContent,
      badge: document.querySelector('#eventsBody .badge').textContent,
      quickLabel: document.querySelector('#eventsBody .event-quick-btn')?.textContent?.trim(),
    }))()`);
    assert.equal(rows.count, 1);
    assert.equal(rows.host, 'www.baidu.com');
    assert.equal(rows.badge, '直连');
    assert.equal(rows.quickLabel, '改代理');
    await browser.evaluate("document.querySelector('#eventsBody .event-quick-btn').click()");
    const deadline = Date.now() + 5000;
    let quickReq;
    while (Date.now() < deadline) {
      quickReq = requests.findLast((r) => r.path === '/api/rules/quick-add');
      if (quickReq) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.deepEqual(quickReq?.body, { host: 'www.baidu.com', action: 'PROXY' });
    await browser.evaluate("document.querySelector('#eventChips [data-efilter=\"all\"]').click()");

    await browser.evaluate(`(() => {
      const input = document.querySelector('#eventSearch');
      input.value = 'xiaohongshu';
      input.dispatchEvent(new Event('input', { bubbles: true }));
    })()`);
    assert.equal(await browser.evaluate("document.querySelectorAll('#eventsBody .event-row').length"), 1);
    assert.equal(await browser.evaluate("document.querySelector('#eventsBody .event-host .h').textContent"), 'www.xiaohongshu.com');
    assert.equal(await browser.evaluate("document.querySelector('#btnEventSearchClear').hidden"), false);

    await browser.evaluate(`(() => {
      const input = document.querySelector('#eventSearch');
      input.value = 'no-such-domain-xyz';
      input.dispatchEvent(new Event('input', { bubbles: true }));
    })()`);
    assert.equal(await browser.evaluate("document.querySelectorAll('#eventsBody .event-row').length"), 0);
    assert.equal(await browser.evaluate("!!document.querySelector('#btnClearEventFilters')"), true);
    await browser.evaluate("document.querySelector('#btnClearEventFilters').click()");
    assert.equal(await browser.evaluate("document.querySelectorAll('#eventsBody .event-row').length"), 3);

    const largeRenderCount = await browser.evaluate(`(() => {
      const backup = STATE.proxy_events.slice();
      STATE.proxy_events = Array.from({ length: 60 }, (_, i) => ({
        time: '14:10:00',
        host: 'svc-' + i + '.example',
        action: i % 2 === 0 ? 'PROXY' : 'DIRECT',
        ok: true,
        rule: 'MATCH,PROXY',
      }));
      renderEvents();
      const rendered = document.querySelectorAll('#eventsBody .event-row').length;
      STATE.proxy_events = backup;
      renderEvents();
      return rendered;
    })()`);
    assert.equal(largeRenderCount, 60);

    const savedEvents = state.proxy_events.slice();
    await browser.evaluate("document.querySelector('#btnClearEvents').click()");
    await browser.waitFor("document.querySelectorAll('#eventsBody .event-row').length === 0");
    assert.equal(await browser.evaluate("document.querySelector('#btnClearEvents').disabled"), true);
    assert.equal(await browser.evaluate("document.querySelector('#eventsCount').textContent"), '0');
    assert.ok(requests.some((r) => r.path === '/api/events/clear'));
    state.proxy_events = savedEvents;
    await browser.evaluate(`STATE.proxy_events = ${JSON.stringify(savedEvents)}; renderEvents();`);
  });

  await t.test('rules view provides code editor with line numbers, Tab/Shift+Tab, Enter auto-indent, Ctrl+/, and domain testing', async () => {
    await browser.evaluate("document.querySelector('#navRules').click()");
    await browser.waitFor("document.querySelector('#viewRules').hidden === false");
    await browser.waitFor("document.querySelector('#rulesContent').value.includes('MATCH,PROXY')");

    // Verify line-number gutter, syntax highlight overlay, and matched rule highlighting
    await browser.evaluate("document.querySelector('#ruleTestHost').value = 'https://www.baidu.com/s'");
    await browser.evaluate("document.querySelector('#btnRuleTest').click()");
    await browser.waitFor("document.querySelector('#ruleTestResult').hidden === false");
    const testInfo = await browser.evaluate(`(() => ({
      testText: document.querySelector('#ruleTestResult').textContent,
      gutterCount: document.querySelectorAll('#rulesGutter .gutter-num').length,
      highlightLines: document.querySelectorAll('#rulesHighlight .code-line').length,
      matchedGutter: document.querySelector('#rulesGutter .gutter-num.is-match')?.textContent || '',
      hasDirectToken: !!document.querySelector('#rulesHighlight .tok-direct'),
      hasProxyToken: !!document.querySelector('#rulesHighlight .tok-proxy'),
    }))()`);
    assert.match(testInfo.testText, /DOMAIN-SUFFIX,baidu\.com,DIRECT/);
    assert.equal(testInfo.gutterCount, 4);
    assert.equal(testInfo.highlightLines, 4);
    assert.equal(testInfo.matchedGutter, '2');
    assert.equal(testInfo.hasDirectToken, true);
    assert.equal(testInfo.hasProxyToken, true);
    if (process.env.DROIDBRIDGE_UI_SHOT_RULES) {
      const shot = await browser.send('Page.captureScreenshot', { format: 'png' });
      await writeFile(process.env.DROIDBRIDGE_UI_SHOT_RULES, Buffer.from(shot.data, 'base64'));
    }

    // Verify real code editor keyboard shortcuts: Tab indent, Shift+Tab outdent, Enter smart indent, Ctrl+/ comment toggle, template insert
    const editorBehavior = await browser.evaluate(`(() => {
      const ta = document.querySelector('#rulesContent');
      ta.value = 'rules:\\n- DOMAIN,a.test,DIRECT\\n- MATCH,PROXY';
      syncRulesEditor();

      // 1) Multi-line Tab indent on lines 2-3
      const line2Start = ta.value.indexOf('- DOMAIN');
      ta.focus();
      ta.setSelectionRange(line2Start, ta.value.length);
      ta.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true }));
      const afterTab = ta.value;

      // 2) Shift+Tab outdent back
      ta.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', shiftKey: true, bubbles: true, cancelable: true }));
      const afterShiftTab = ta.value;

      // 3) Re-indent then Ctrl+/ toggle comment on line 2
      ta.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true }));
      const l2 = ta.value.indexOf('  - DOMAIN');
      ta.setSelectionRange(l2 + 3, l2 + 3);
      ta.dispatchEvent(new KeyboardEvent('keydown', { key: '/', ctrlKey: true, bubbles: true, cancelable: true }));
      const afterComment = ta.value;
      ta.dispatchEvent(new KeyboardEvent('keydown', { key: '/', ctrlKey: true, bubbles: true, cancelable: true }));
      const afterUncomment = ta.value;

      // 4) Enter at end of rule line auto-inserts "  - "
      const l2End = ta.value.indexOf('DIRECT') + 'DIRECT'.length;
      ta.setSelectionRange(l2End, l2End);
      ta.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
      const afterEnter = ta.value;

      // 5) Template button inserts rule above MATCH
      ta.value = 'rules:\\n  - MATCH,PROXY\\n';
      syncRulesEditor();
      document.querySelector('.editor-tpl-btn[data-rtpl="DOMAIN,example.com,DIRECT"]').click();
      const afterTpl = ta.value;
      const dirtyVisible = !document.querySelector('#rulesDirtyBadge').hidden;
      const cursorText = document.querySelector('#rulesCursorPos').textContent;
      return { afterTab, afterShiftTab, afterComment, afterUncomment, afterEnter, afterTpl, dirtyVisible, cursorText };
    })()`);
    assert.equal(editorBehavior.afterTab, 'rules:\n  - DOMAIN,a.test,DIRECT\n  - MATCH,PROXY');
    assert.equal(editorBehavior.afterShiftTab, 'rules:\n- DOMAIN,a.test,DIRECT\n- MATCH,PROXY');
    assert.equal(editorBehavior.afterComment, 'rules:\n  # - DOMAIN,a.test,DIRECT\n  - MATCH,PROXY');
    assert.equal(editorBehavior.afterUncomment, 'rules:\n  - DOMAIN,a.test,DIRECT\n  - MATCH,PROXY');
    assert.equal(editorBehavior.afterEnter, 'rules:\n  - DOMAIN,a.test,DIRECT\n  - \n  - MATCH,PROXY');
    assert.equal(editorBehavior.afterTpl, 'rules:\n  - DOMAIN,example.com,DIRECT\n  - MATCH,PROXY\n');
    assert.equal(editorBehavior.dirtyVisible, true);
    assert.match(editorBehavior.cursorText, /第 2 行/);

    // Verify Ctrl+S saves rules directly
    await browser.evaluate(`(() => {
      const ta = document.querySelector('#rulesContent');
      ta.value = 'rules:\\n  - DOMAIN,new.test,DIRECT\\n  - MATCH,PROXY\\n';
      syncRulesEditor();
      ta.focus();
      ta.dispatchEvent(new KeyboardEvent('keydown', { key: 's', ctrlKey: true, bubbles: true, cancelable: true }));
    })()`);
    const deadline = Date.now() + 5000;
    let saveReq;
    while (Date.now() < deadline) {
      saveReq = requests.findLast((r) => r.path === '/api/rules');
      if (saveReq) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(saveReq);
    assert.match(saveReq.body.content, /DOMAIN,new\.test,DIRECT/);
  });

  await t.test('multi-device ADB selector in settings view passes serial and refreshes proxy chain immediately', async () => {
    await browser.evaluate("document.querySelector('#navSettings').click()");
    await browser.waitFor("document.querySelector('#viewSettings').hidden === false");
    if (process.env.DROIDBRIDGE_UI_SHOT_SETTINGS) {
      const shot = await browser.send('Page.captureScreenshot', { format: 'png' });
      await writeFile(process.env.DROIDBRIDGE_UI_SHOT_SETTINGS, Buffer.from(shot.data, 'base64'));
    }
    const beforeStateCount = requests.filter((r) => r.path === '/api/state').length;
    await browser.evaluate(`(() => {
      ADB_STATE = {
        adb_found: true,
        adb_path: 'C:\\\\fake\\\\adb.exe',
        devices: [
          { serial: 'DEV-1', model: 'Phone A', state: 'device' },
          { serial: 'DEV-2', model: 'Phone B', state: 'device' },
        ],
        forwards: [],
        upstream_port: 5038,
        selected_serial: 'DEV-1',
        error: '',
      };
      SELECTED_ADB_SERIAL = '';
      renderAdb();
      const sel = document.querySelector('#adbDeviceSelect');
      sel.value = 'DEV-2';
      sel.dispatchEvent(new Event('change', { bubbles: true }));
    })()`);
    assert.equal(await browser.evaluate("document.querySelector('#adbDevicePickerRow').hidden"), false);
    await browser.evaluate("document.querySelector('#btnAdbForward').click()");
    const deadline = Date.now() + 5000;
    let fwdReq;
    while (Date.now() < deadline) {
      fwdReq = requests.findLast((r) => r.path === '/api/adb/forward');
      if (fwdReq && requests.filter((r) => r.path === '/api/state').length > beforeStateCount) break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.deepEqual(fwdReq?.body, { serial: 'DEV-2' });
    assert.ok(requests.filter((r) => r.path === '/api/state').length > beforeStateCount);
  });

  await t.test('shows Firefox profile tools and tray residency controls when applicable', async () => {
    await browser.evaluate("document.querySelector('#navApps').click()");
    await browser.waitFor("document.querySelector('#viewApps').hidden === false");
    const ffVisible = await browser.evaluate(`(() => {
      openEditor({
        ...STATE.apps[0],
        id: 'ff-test',
        name: 'FireFox',
        effective_kind: 'firefox',
        firefox_profile_dir: 'S:\\\\Mydevelop\\\\DroidBridge\\\\profiles\\\\ff-test',
      });
      const shown = !document.querySelector('#ffProfileTools').hidden;
      const fields = [...document.querySelectorAll('#editor input, #editor select')].map((el) => el.id);
      closeEditor();
      return { shown, fields };
    })()`);
    assert.equal(ffVisible.shown, true);
    assert.deepEqual(ffVisible.fields, ['fName', 'fExe', 'fArgs', 'fKind', 'fNote']);

    const trayFooter = await browser.evaluate(`(() => {
      STATE.tray_active = true;
      render();
      const result = {
        quitHidden: document.querySelector('#btnQuitService').hidden,
        settingsQuitHidden: document.querySelector('#btnSettingsQuit').hidden,
        footText: document.querySelector('#footText').textContent,
      };
      STATE.tray_active = false;
      render();
      return result;
    })()`);
    assert.equal(trayFooter.quitHidden, false);
    assert.equal(trayFooter.settingsQuitHidden, false);
    assert.match(trayFooter.footText, /托盘常驻/);
  });

  await t.test('delete asks in-app and undo restores the app', async () => {
    await browser.evaluate("document.querySelector('#navApps').click()");
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

  await t.test('editor only edits application launch settings and escape closes it', async () => {
    await browser.evaluate("document.querySelector('#btnAdd').click()");
    await browser.waitFor("document.querySelector('#editor').hidden === false");
    const editor = await browser.evaluate(`(() => ({
      hasAppBypass: !!document.querySelector('#fBypass'),
      fields: [...document.querySelectorAll('#editor input, #editor select')].map((el) => el.id),
    }))()`);
    assert.equal(editor.hasAppBypass, false);
    assert.deepEqual(editor.fields, ['fName', 'fExe', 'fArgs', 'fKind', 'fNote']);
    await browser.evaluate("document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))");
    assert.equal(await browser.evaluate("document.querySelector('#editor').hidden"), true);
  });

  await t.test('mobile layout has no horizontal overflow across views', async () => {
    await browser.evaluate("document.querySelector('#navApps').click()");
    await browser.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const layout = await browser.evaluate(`(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      innerWidth: window.innerWidth,
      chainVisible: !!document.querySelector('#chainPanel').offsetHeight,
      addVisible: !!document.querySelector('#btnAdd').offsetHeight,
      mobileToggleVisible: !!document.querySelector('#mobileProxyEnabled').offsetHeight,
      summaryVisible: !!document.querySelector('#mobileChainSummary').offsetHeight,
      summaryText: document.querySelector('#mobileChainText').textContent,
      summaryMeta: document.querySelector('#mobileChainMeta').textContent,
      railBelow: document.querySelector('#statusRail').getBoundingClientRect().top > document.querySelector('#appGrid').getBoundingClientRect().bottom - 1,
      singleColCards: (() => { const c = [...document.querySelectorAll('#appGrid .card')]; return c.length < 2 || Math.abs(c[0].getBoundingClientRect().top - c[1].getBoundingClientRect().top) > 1; })(),
    }))()`);
    assert.equal(layout.innerWidth, 390);
    assert.equal(layout.railBelow, true);
    assert.equal(layout.singleColCards, true);
    assert.ok(layout.scrollWidth <= layout.innerWidth + 1, `horizontal overflow: ${layout.scrollWidth} > ${layout.innerWidth}`);
    assert.equal(layout.chainVisible, true);
    assert.equal(layout.addVisible, true);
    assert.equal(layout.mobileToggleVisible, true);
    assert.equal(layout.summaryVisible, true);
    assert.equal(layout.summaryText, '链路畅通');
    assert.match(layout.summaryMeta, /入口 12ms · Clash 8ms/);
    if (process.env.DROIDBRIDGE_UI_SHOT_MOBILE) {
      const shot = await browser.send('Page.captureScreenshot', { format: 'png' });
      await writeFile(process.env.DROIDBRIDGE_UI_SHOT_MOBILE, Buffer.from(shot.data, 'base64'));
    }

    for (const navId of ['#navTraffic', '#navRules', '#navSettings']) {
      await browser.evaluate(`document.querySelector(${JSON.stringify(navId)}).click()`);
      await new Promise((resolve) => setTimeout(resolve, 80));
      const overflow = await browser.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 1');
      assert.equal(overflow, true, `mobile horizontal overflow on ${navId}`);
    }
  });

  assert.deepEqual(browser.runtimeErrors, []);
});
