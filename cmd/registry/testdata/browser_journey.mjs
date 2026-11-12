// Drives the web interface in a real headless Chromium over the DevTools
// Protocol, with no npm dependencies. Usage: node browser_journey.mjs
// <devtools-port> <registry-origin> <admin-login> <admin-password>
// <mailpit-api-url>
import crypto from "node:crypto";

const [port, origin, login, password, mailpit] = process.argv.slice(2);
const step = (name) => console.log("step:", name);

const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
const page = targets.find((t) => t.type === "page");
const socket = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
let nextID = 0;
const pending = new Map();
socket.onmessage = (event) => {
  const message = JSON.parse(event.data);
  if (message.id && pending.has(message.id)) {
    const { resolve, reject } = pending.get(message.id);
    pending.delete(message.id);
    message.error ? reject(new Error(JSON.stringify(message.error))) : resolve(message.result);
  }
};
const send = (method, params = {}) => new Promise((resolve, reject) => {
  const id = ++nextID;
  pending.set(id, { resolve, reject });
  socket.send(JSON.stringify({ id, method, params }));
});
const evaluate = async (expression) => {
  const result = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true, userGesture: true });
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
  return result.result.value;
};
const waitFor = async (expression, what, timeout = 15000) => {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await evaluate(expression).catch(() => false)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  const text = await evaluate("location.hash + \"\\n\" + document.body.innerText").catch(() => "");
  throw new Error(`timed out waiting for ${what}; page shows:\n${text}`);
};
const text = () => evaluate("document.getElementById('app').innerText + '\\n' + document.getElementById('toast').innerText");
const fill = (name, value) => evaluate(`(() => { const el = document.querySelector('[name=${JSON.stringify(name)}]'); el.value = ${JSON.stringify(value)}; el.dispatchEvent(new Event('input', {bubbles:true})); return true; })()`);
const choose = (name, value) => evaluate(`(() => { const el = document.querySelector('select[name=${JSON.stringify(name)}]'); el.value = ${JSON.stringify(value)}; return el.value === ${JSON.stringify(value)}; })()`);
const submit = (label) => evaluate(`(() => { const b = [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === ${JSON.stringify(label)}); if (!b) throw new Error('no button ' + ${JSON.stringify(label)}); b.click(); return true; })()`);
const visit = async (hash) => { await evaluate(`location.hash = ${JSON.stringify(hash)}`); await new Promise((r) => setTimeout(r, 300)); };
const has = (fragment) => `document.body.innerText.includes(${JSON.stringify(fragment)})`;
function totp(secretBase32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secretBase32.replace(/=+$/, "")) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const mac = crypto.createHmac("sha1", key).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, "0");
}

// Waits for an email whose subject contains subject and returns the link
// to route found in its text body.
async function emailedLink(recipient, subject, route) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const listing = await (await fetch(`${mailpit}/api/v1/messages`)).json();
    for (const message of listing.messages || []) {
      if (message.To.length === 1 && message.To[0].Address === recipient && message.Subject.includes(subject)) {
        const detail = await (await fetch(`${mailpit}/api/v1/message/${message.ID}`)).json();
        const match = detail.Text.match(new RegExp(origin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "/#/" + route + "\\?token=[A-Za-z0-9%._-]+"));
        if (match) return match[0];
      }
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`no "${subject}" email with a ${route} link reached ${recipient}`);
}

await send("Runtime.enable");
await send("Page.enable");
await send("Page.navigate", { url: origin + "/#/login" });
await waitFor("document.querySelector('[name=login_name]') !== null", "login form");
const csp = await evaluate("fetch('/').then((r) => r.headers.get('content-security-policy'))");
if (!csp.includes("script-src 'self'")) throw new Error("missing CSP: " + csp);

step("password login leads to TOTP enrollment");
await fill("login_name", login);
await fill("password", password);
await submit("Entrar");
await waitFor(has("Cadastre o TOTP"), "TOTP enrollment");
const secret = await evaluate("document.querySelector('code.secret').textContent");
await fill("code", totp(secret));
await submit("Confirmar");
await waitFor(has("Códigos de recuperação"), "recovery codes");
await submit("Continuar");
await waitFor(has("Novo workspace"), "workspaces page");

step("create workspace and repository");
await fill("slug", "browser-team");
await fill("display_name", "Browser Team");
await submit("Criar");
await waitFor(has("Novo repositório"), "workspace page");
await fill("slug", "web-packages");
await fill("display_name", "Web Packages");
await choose("format", "npm");
await submit("Criar");
await waitFor(has("Como usar"), "repository page");
await waitFor(has("/npm/"), "npm setup snippet");
const repositoryHash = await evaluate("location.hash");

step("grant access and issue a token");
await visit(repositoryHash + "/grants");
await waitFor("document.querySelector('select[name=user]') !== null", "grant form");
await choose("role", "reader");
await submit("Conceder");
await waitFor(has("Revogar"), "granted role listed");
await visit(repositoryHash + "/tokens");
await waitFor(has("Novo token"), "tokens tab");
await submit("Gerar");
await waitFor("document.querySelector('code.secret') !== null", "issued token");
const token = await evaluate("document.querySelector('code.secret').textContent");
if (!/^prpt_|^pr[a-z]+_/.test(token)) throw new Error("unexpected token: " + token);
await waitFor(has("ativo"), "token listed as active");

step("invitation link");
const workspaceHash = repositoryHash.split("/r/")[0];
await visit(workspaceHash + "/invitations");
await waitFor(has("Novo convite"), "invitations tab");
await submit("Criar convite");
await waitFor(has("/#/invite?token="), "invitation link");

step("passkey with a virtual authenticator");
await send("WebAuthn.enable", { enableUI: false });
await send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
// Registering needs a recent second factor, which the TOTP sign-in gave.
await visit("#/account");
await waitFor(has("Adicionar passkey"), "account page");
await fill("name", "Headless Chrome");
await submit("Adicionar passkey");
await waitFor(has("Headless Chrome"), "registered passkey");

step("sign out and sign in with the passkey, without a password");
await evaluate("document.getElementById('logout').click()");
await waitFor(has("Entrar com passkey"), "login page with passkey button");
await submit("Entrar com passkey");
await waitFor(has("Novo workspace"), "workspaces after passkey sign-in");
await waitFor(has("Browser Team"), "the workspace created earlier");
await visit("#/account");
await waitFor(has("MFA recente"), "MFA-level session from the passkey");

step("administration page");
await visit("#/admin");
await waitFor(has("Política atual"), "admin page");

step("confirm an email address from the emailed link");
await visit("#/account");
await waitFor(has("Enviar confirmação"), "email panel");
await fill("email", "browser.admin@example.com");
await submit("Enviar confirmação");
await waitFor(has("Aguardando confirmação"), "pending address");
const verifyLink = await emailedLink("browser.admin@example.com", "Confirme seu e-mail", "verify-email");
await send("Page.navigate", { url: verifyLink });
await waitFor(has("Confirmar que este endereço é seu?"), "confirmation page");
await submit("Confirmar");
await waitFor(has("E-mail confirmado"), "confirmed address");
await visit("#/account");
await waitFor(has("confirmado"), "account shows the confirmed address");

step("forgot password: emailed link sets a new password, second factor still required");
await evaluate("document.getElementById('logout').click()");
await waitFor(has("Esqueci minha senha"), "forgot password link");
await visit("#/forgot");
await fill("login_name", login);
await submit("Enviar link");
await waitFor(has("Verifique seu e-mail"), "request accepted");
const recoverLink = await emailedLink("browser.admin@example.com", "Recuperação", "recover");
await send("Page.navigate", { url: recoverLink });
await waitFor("document.querySelector('[name=password]') !== null", "recovery form");
const newPassword = password + "-renewed";
await fill("password", newPassword);
await submit("Definir");
await waitFor(has("Entrar com passkey"), "back on the login page");
await fill("login_name", login);
await fill("password", newPassword);
await submit("Entrar");
await waitFor(has("Segundo fator"), "second factor still required after recovery");

console.log("browser journey passed");
socket.close();
