"use strict";

// Private Registry web interface. Plain browser JavaScript, no build step and
// no third-party code. Every value from the server is inserted as text, never
// as HTML.

const app = document.getElementById("app");
const state = { session: null, methods: null };

const FORMATS = ["generic", "go", "cargo", "npm", "pub", "oci"];
const WRITE_KINDS = { cargo: "cargo-write", npm: "npm-write", pub: "pub-write", oci: "oci-write" };
const WRITE_TOKEN_PATHS = { cargo: "cargo-write-tokens", npm: "npm-write-tokens", pub: "pub-write-tokens", oci: "oci-write-tokens" };
const MESSAGES = {
  authentication_failed: "Não foi possível autenticar.",
  mfa_required: "Esta ação exige um segundo fator. Cadastre TOTP ou uma passkey em Conta.",
  reauthentication_required: "Por segurança, entre de novo para confirmar sua identidade.",
  csrf_failed: "Sessão inválida. Recarregue a página.",
  forbidden: "Você não tem permissão para isso.",
  rate_limited: "Muitas tentativas. Aguarde um pouco.",
  signup_closed: "O cadastro por convite está desligado nesta instalação.",
  login_name_taken: "Esse nome de login já existe.",
  invitation_unavailable: "Convite inválido, expirado ou já usado.",
  recovery_unavailable: "Link de recuperação inválido, expirado ou já usado.",
  invalid_password: "A senha precisa ter pelo menos 15 caracteres.",
  temporarily_unavailable: "Serviço temporariamente indisponível.",
  email_unavailable: "O envio de e-mail não está configurado nesta instalação.",
  no_verified_email: "Essa conta não tem e-mail confirmado.",
  invalid_email: "Endereço de e-mail inválido.",
  too_many_requests: "Muitos pedidos de confirmação. Tente de novo mais tarde.",
  verification_unavailable: "Link de confirmação inválido, expirado ou já usado.",
};

// ---------- helpers ----------

function el(tag, attributes, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key === "class") node.className = value;
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function cookie(name) {
  for (const part of document.cookie.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return "";
}

class ApiError extends Error {
  constructor(status, code) {
    super(MESSAGES[code] || code || "HTTP " + status);
    this.status = status;
    this.code = code;
  }
}

async function api(method, path, body, raw) {
  const headers = {};
  if (method !== "GET") headers["X-CSRF-Token"] = cookie("__Host-registry-csrf");
  let payload;
  if (raw !== undefined) {
    payload = raw;
    headers["Content-Type"] = "application/json";
  } else if (body !== undefined) {
    payload = JSON.stringify(body);
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(path, { method, headers, body: payload, credentials: "same-origin", cache: "no-store" });
  if (response.status === 204) return null;
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const code = data && data.error && (data.error.code || data.error);
    const error = new ApiError(response.status, typeof code === "string" ? code : "");
    if (error.code === "reauthentication_required") {
      toast(error.message, true);
      setTimeout(() => go("#/login"), 1200);
    }
    throw error;
  }
  return data;
}

function toast(message, isError) {
  const node = document.getElementById("toast");
  node.textContent = message;
  node.className = isError ? "error" : "";
  node.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { node.hidden = true; }, 5000);
}

function go(hash) { if (location.hash === hash) render(); else location.hash = hash; }

function when(promise) {
  return promise.catch((error) => { toast(error.message, true); throw error; });
}

function formatDate(value) {
  if (!value) return "";
  const date = new Date(value);
  return isNaN(date) ? value : date.toLocaleString();
}

function field(label, input) { return [el("label", {}, label), input]; }

function table(headers, rows) {
  return el("table", {}, el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, rows.length ? rows : el("tr", {}, el("td", { colspan: headers.length, class: "muted" }, "Nada aqui ainda."))));
}

function secret(title, value, note) {
  return el("div", { class: "panel" }, el("strong", {}, title), el("code", { class: "secret" }, value),
    el("p", { class: "muted" }, note || "Copie agora: não será mostrado de novo."),
    el("button", { class: "secondary", type: "button", onclick: () => navigator.clipboard && navigator.clipboard.writeText(value).then(() => toast("Copiado.")) }, "Copiar"));
}

function form(submitLabel, children, onsubmit) {
  const node = el("form", {}, children, el("div", { class: "actions" }, el("button", { type: "submit" }, submitLabel)));
  node.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = node.querySelector("button[type=submit]");
    button.disabled = true;
    try { await onsubmit(new FormData(node)); } catch (error) { if (!(error instanceof ApiError)) toast(error.message, true); }
    finally { button.disabled = false; }
  });
  return node;
}

function input(name, attributes) { return el("input", Object.assign({ name, id: name }, attributes || {})); }

function select(name, options, selected) {
  return el("select", { name, id: name }, options.map((value) => el("option", { value, selected: value === selected }, value)));
}

function ttlSeconds(days) { return Math.round(Number(days || 0) * 86400); }

// ---------- WebAuthn ----------

const b64 = {
  decode(value) {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
    return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0)).buffer;
  },
  encode(buffer) {
    let text = "";
    for (const byte of new Uint8Array(buffer)) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
};

function credentialJSON(credential) {
  const response = {};
  for (const key of ["clientDataJSON", "attestationObject", "authenticatorData", "signature", "userHandle"]) {
    if (credential.response[key]) response[key] = b64.encode(credential.response[key]);
  }
  if (credential.response.getTransports) response.transports = credential.response.getTransports();
  return JSON.stringify({ id: credential.id, rawId: b64.encode(credential.rawId), type: credential.type, response, clientExtensionResults: credential.getClientExtensionResults(), authenticatorAttachment: credential.authenticatorAttachment || undefined });
}

async function passkeyLogin() {
  const options = await when(api("POST", "/api/v1/auth/passkeys/login/start"));
  const publicKey = options.publicKey;
  publicKey.challenge = b64.decode(publicKey.challenge);
  (publicKey.allowCredentials || []).forEach((c) => { c.id = b64.decode(c.id); });
  const credential = await navigator.credentials.get({ publicKey });
  await when(api("POST", "/api/v1/auth/passkeys/login/finish", undefined, credentialJSON(credential)));
  await loadSession();
  go("#/");
}

async function passkeyRegister(name) {
  const options = await when(api("POST", "/api/v1/auth/passkeys/registration/start", { name }));
  const publicKey = options.publicKey;
  publicKey.challenge = b64.decode(publicKey.challenge);
  publicKey.user.id = b64.decode(publicKey.user.id);
  (publicKey.excludeCredentials || []).forEach((c) => { c.id = b64.decode(c.id); });
  const credential = await navigator.credentials.create({ publicKey });
  await when(api("POST", "/api/v1/auth/passkeys/registration/finish", undefined, credentialJSON(credential)));
  toast("Passkey cadastrada.");
}

// ---------- session ----------

async function loadSession() {
  try { state.session = await api("GET", "/api/v1/auth/session"); } catch { state.session = null; }
  const signedIn = state.session && (state.session.level === "standard" || state.session.level === "mfa");
  document.getElementById("nav").hidden = !signedIn;
  const admin = document.getElementById("nav-admin");
  admin.hidden = !(signedIn && state.session.instance_admin);
  if (!admin.hidden) refreshEmailAlert();
  return state.session;
}

// Administrators see a marker on the menu while emails are failing.
async function refreshEmailAlert() {
  const admin = document.getElementById("nav-admin");
  const status = await api("GET", "/api/v1/admin/email").catch(() => null);
  const failing = status && status.enabled && status.health !== "ok";
  admin.replaceChildren("Administração", failing ? el("span", { class: "badge alert", title: "Há e-mails com problema" }, " e-mail ") : "");
}

document.getElementById("logout").addEventListener("click", async () => {
  try { await api("POST", "/api/v1/auth/logout"); } catch { /* the session may already be gone */ }
  state.session = null;
  await loadSession();
  go("#/login");
});

// ---------- pages ----------

function loginPage(params) {
  const root = el("div", { class: "narrow" });
  const stage = el("div");
  const show = (...nodes) => stage.replaceChildren(...nodes);

  const passwordForm = form("Entrar", [field("Login", input("login_name", { autocomplete: "username", required: true })), field("Senha", input("password", { type: "password", autocomplete: "current-password", required: true }))], async (data) => {
    const result = await when(api("POST", "/api/v1/auth/login", { login_name: data.get("login_name"), password: data.get("password") }));
    nextStage(result.stage);
  });

  async function nextStage(name) {
    if (name === "authenticated") { await loadSession(); go("#/"); return; }
    if (name === "mfa_challenge") {
      show(el("h2", {}, "Segundo fator"), form("Confirmar", [field("Código do aplicativo ou código de recuperação", input("code", { autocomplete: "one-time-code", required: true }))], async (data) => {
        await when(api("POST", "/api/v1/auth/mfa/challenge", { code: data.get("code") }));
        await loadSession();
        go("#/");
      }));
      return;
    }
    if (name === "mfa_enrollment") {
      const enrollment = await when(api("POST", "/api/v1/auth/mfa/enrollment"));
      show(el("h2", {}, "Cadastre o TOTP"), el("p", { class: "muted" }, "Esta conta precisa de um segundo fator. Adicione esta chave ao seu aplicativo autenticador:"),
        el("code", { class: "secret" }, enrollment.secret), el("code", { class: "secret" }, enrollment.otpauth_url),
        form("Confirmar", [field("Código de 6 dígitos", input("code", { autocomplete: "one-time-code", required: true }))], async (data) => {
          const result = await when(api("POST", "/api/v1/auth/mfa/enrollment/complete", { code: data.get("code") }));
          await loadSession();
          show(secret("Códigos de recuperação", result.recovery_codes.join("  "), "Guarde num lugar seguro. Cada código funciona uma vez."), el("button", { type: "button", onclick: () => go("#/") }, "Continuar"));
        }));
    }
  }

  const methods = el("div", { class: "actions" });
  if (state.methods && state.methods.passkeys && window.PublicKeyCredential) methods.append(el("button", { type: "button", class: "secondary", onclick: () => passkeyLogin().catch(() => {}) }, "Entrar com passkey"));
  if (state.methods && state.methods.muira) methods.append(el("button", { type: "button", class: "secondary", onclick: () => { location.href = "/api/v1/auth/muira/start"; } }, "Entrar com Muira"));

  const forgot = state.methods && state.methods.email_recovery ? el("p", { class: "muted" }, el("a", { href: "#/forgot" }, "Esqueci minha senha")) : "";
  show(passwordForm, methods, forgot);
  root.append(el("div", { class: "panel" }, el("h1", {}, "Entrar"), stage));
  if (params.get("error")) toast("A autenticação externa falhou.", true);
  if (params.get("stage")) nextStage(params.get("stage"));
  return root;
}

async function workspacesPage() {
  const data = await when(api("GET", "/api/v1/workspaces?limit=100"));
  const rows = data.workspaces.map((w) => el("tr", {}, el("td", {}, el("a", { href: "#/w/" + w.workspace_id }, w.display_name)), el("td", {}, el("code", {}, w.slug)), el("td", {}, w.role)));
  return el("div", {}, el("h1", {}, "Workspaces"), el("div", { class: "panel" }, table(["Nome", "Slug", "Seu papel"], rows)),
    el("div", { class: "panel" }, el("h2", {}, "Novo workspace"), form("Criar", [el("div", { class: "row" }, el("div", {}, field("Slug", input("slug", { required: true, pattern: "[a-z0-9-]+" }))), el("div", {}, field("Nome", input("display_name", { required: true }))))], async (form) => {
      const created = await when(api("POST", "/api/v1/workspaces", { slug: form.get("slug"), display_name: form.get("display_name") }));
      go("#/w/" + created.workspace_id);
    })));
}

function tabs(base, current, entries) {
  return el("div", { class: "tabs" }, entries.map(([key, label]) => el("a", { href: base + "/" + key, class: key === current ? "active" : "" }, label)));
}

async function workspacePage(workspace, tab) {
  const base = "#/w/" + workspace;
  const workspaces = await when(api("GET", "/api/v1/workspaces?limit=100"));
  const current = workspaces.workspaces.find((w) => w.workspace_id === workspace);
  if (!current) throw new Error("Workspace não encontrado.");
  const manager = current.role === "owner" || current.role === "administrator";
  const entries = [["repositories", "Repositórios"], ["members", "Membros"]];
  if (manager) entries.push(["invitations", "Convites"], ["service-accounts", "Contas de serviço"]);
  tab = tab || "repositories";
  const body = el("div");
  const page = el("div", {}, el("h1", {}, current.display_name), tabs(base, tab, entries), body);
  if (tab === "repositories") body.append(await repositoriesTab(workspace, manager));
  if (tab === "members") body.append(await membersTab(workspace, current.role));
  if (tab === "invitations" && manager) body.append(await invitationsTab(workspace, current.role));
  if (tab === "service-accounts" && manager) body.append(await serviceAccountsTab(workspace));
  return page;
}

async function repositoriesTab(workspace, manager) {
  const data = await when(api("GET", "/api/v1/workspaces/" + workspace + "/repositories?limit=100"));
  const rows = data.repositories.map((r) => el("tr", {}, el("td", {}, el("a", { href: "#/w/" + workspace + "/r/" + r.repository_id }, r.display_name)), el("td", {}, el("span", { class: "badge" }, r.format)), el("td", {}, r.visibility)));
  const nodes = [el("div", { class: "panel" }, table(["Repositório", "Formato", "Visibilidade"], rows))];
  if (manager) {
    nodes.push(el("div", { class: "panel" }, el("h2", {}, "Novo repositório"), form("Criar", [el("div", { class: "row" }, el("div", {}, field("Slug", input("slug", { required: true }))), el("div", {}, field("Nome", input("display_name", { required: true }))), el("div", {}, field("Formato", select("format", FORMATS, "npm"))))], async (form) => {
      const created = await when(api("POST", "/api/v1/workspaces/" + workspace + "/repositories", { slug: form.get("slug"), display_name: form.get("display_name"), format: form.get("format") }));
      go("#/w/" + workspace + "/r/" + created.repository_id);
    })));
  }
  return el("div", {}, nodes);
}

async function membersTab(workspace, role) {
  const data = await when(api("GET", "/api/v1/workspaces/" + workspace + "/members"));
  const canManage = role === "owner" || role === "administrator";
  const rows = data.members.map((m) => el("tr", {}, el("td", {}, m.display_name), el("td", {}, el("code", {}, m.login_name || "—")), el("td", {}, m.role, m.service_account ? " (serviço)" : ""), el("td", {}, el("code", {}, m.user_id)),
    el("td", {}, canManage && m.user_id !== state.session.user_id ? el("button", { class: "danger", type: "button", onclick: async () => {
      if (!confirm("Remover " + m.display_name + " do workspace?")) return;
      await when(api("DELETE", "/api/v1/workspaces/" + workspace + "/members/" + m.user_id));
      go("#/w/" + workspace + "/members");
    } }, "Remover") : "")));
  return el("div", { class: "panel" }, table(["Nome", "Login", "Papel", "ID", ""], rows));
}

async function invitationsTab(workspace, role) {
  const data = await when(api("GET", "/api/v1/workspaces/" + workspace + "/invitations"));
  const created = el("div");
  const roles = role === "owner" ? ["member", "administrator"] : ["member"];
  const rows = data.invitations.map((i) => el("tr", {}, el("td", {}, i.role), el("td", {}, i.email || "link"), el("td", {}, i.state), el("td", {}, formatDate(i.expires_at)),
    el("td", {}, i.state === "pending" ? el("button", { class: "danger", type: "button", onclick: async () => {
      await when(api("DELETE", "/api/v1/workspaces/" + workspace + "/invitations/" + i.invitation_id));
      go("#/w/" + workspace + "/invitations");
    } }, "Revogar") : "")));
  return el("div", {}, created, el("div", { class: "panel" }, el("h2", {}, "Novo convite"), form("Criar convite", [el("div", { class: "row" }, el("div", {}, field("Papel", select("role", roles, "member"))), el("div", {}, field("Validade (dias)", input("days", { type: "number", min: "1", max: "30", value: "7" }))),
    state.methods && state.methods.email_recovery ? el("div", {}, field("E-mail (opcional: envia o convite)", input("email", { type: "email", autocomplete: "off" }))) : "")], async (form) => {
    const email = (form.get("email") || "").trim();
    const invitation = await when(api("POST", "/api/v1/workspaces/" + workspace + "/invitations", { role: form.get("role"), ttl_seconds: ttlSeconds(form.get("days")), email: email || undefined }));
    if (invitation.email) {
      toast("Convite enviado para " + invitation.email + ".");
      go("#/w/" + workspace + "/invitations");
      return;
    }
    const link = location.origin + "/#/invite?token=" + encodeURIComponent(invitation.token);
    created.replaceChildren(secret("Link do convite", link, "Envie por um canal seu. Funciona uma vez e expira em " + formatDate(invitation.expires_at) + "."));
  })), el("div", { class: "panel" }, table(["Papel", "Enviado para", "Estado", "Expira", ""], rows)));
}

async function serviceAccountsTab(workspace) {
  const data = await when(api("GET", "/api/v1/workspaces/" + workspace + "/service-accounts"));
  const rows = data.service_accounts.map((a) => el("tr", {}, el("td", {}, a.description), el("td", {}, a.status), el("td", {}, el("code", {}, a.user_id)),
    el("td", {}, a.status === "active" ? el("button", { class: "danger", type: "button", onclick: async () => {
      if (!confirm("Desativar " + a.description + "? Os tokens dela param de funcionar.")) return;
      await when(api("DELETE", "/api/v1/workspaces/" + workspace + "/service-accounts/" + a.user_id));
      go("#/w/" + workspace + "/service-accounts");
    } }, "Desativar") : "")));
  return el("div", {}, el("div", { class: "panel" }, el("p", { class: "muted" }, "Contas de serviço não entram pela interface. Dê a elas grants nos repositórios e emita tokens ou configure trusted publishing na página do repositório."), table(["Descrição", "Estado", "ID", ""], rows)),
    el("div", { class: "panel" }, el("h2", {}, "Nova conta de serviço"), form("Criar", [field("Descrição", input("description", { required: true }))], async (form) => {
      await when(api("POST", "/api/v1/workspaces/" + workspace + "/service-accounts", { description: form.get("description") }));
      go("#/w/" + workspace + "/service-accounts");
    })));
}

async function repositoryPage(workspace, repository, tab) {
  const repositories = await when(api("GET", "/api/v1/workspaces/" + workspace + "/repositories?limit=100"));
  const current = repositories.repositories.find((r) => r.repository_id === repository);
  if (!current) throw new Error("Repositório não encontrado.");
  const base = "#/w/" + workspace + "/r/" + repository;
  const entries = [["setup", "Como usar"], ["tokens", "Meus tokens"], ["grants", "Acesso"]];
  if (WRITE_KINDS[current.format]) entries.push(["ci", "CI"]);
  if (current.format === "oci") entries.push(["reviews", "Revisões"]);
  tab = tab || "setup";
  const body = el("div");
  const page = el("div", {}, el("p", {}, el("a", { href: "#/w/" + workspace }, "← workspace")), el("h1", {}, current.display_name, " ", el("span", { class: "badge" }, current.format)), tabs(base, tab, entries), body);
  if (tab === "setup") body.append(setupTab(workspace, current));
  if (tab === "tokens") body.append(await tokensTab(workspace, current));
  if (tab === "grants") body.append(await grantsTab(workspace, current));
  if (tab === "ci") body.append(await ciTab(workspace, current));
  if (tab === "reviews") body.append(await reviewsTab(workspace, current));
  return page;
}

function setupTab(workspace, repository) {
  const origin = location.origin;
  const host = location.host;
  const id = repository.repository_id;
  const snippets = {
    npm: "@escopo:registry=" + origin + "/npm/" + workspace + "/" + id + "/\n//" + host + "/npm/" + workspace + "/" + id + "/:_authToken=<TOKEN>",
    cargo: "[registries.private]\nindex = \"sparse+" + origin + "/cargo/" + workspace + "/" + id + "/index/\"\ncredential-provider = \"private-registry\"\n\n[credential-alias]\nprivate-registry = [\"registryctl\", \"-index\", \"sparse+" + origin + "/cargo/" + workspace + "/" + id + "/index/\", \"-read-token-file\", \"<arquivo>\", \"-write-token-file\", \"<arquivo>\"]",
    pub: "dart pub token add " + origin + "/pub/" + workspace + "/" + id,
    oci: "oras login " + host + " -u token --password-stdin <<< \"$TOKEN\"\noras push " + host + "/" + workspace + "/" + id + "/<imagem>:<tag> ./arquivo",
    go: "GOPROXY=" + origin + "/go/" + workspace + "/" + id + "\nGONOSUMDB=<seu módulo>\n# credenciais em ~/.netrc com o token de leitura",
    generic: "Envio e download pela API: /api/v1/workspaces/" + workspace + "/repositories/" + id + "/artifacts",
  };
  return el("div", { class: "panel" }, el("p", { class: "muted" }, "Configuração do cliente. Gere os tokens na aba “Meus tokens”."), el("code", { class: "secret" }, snippets[repository.format] || ""), el("p", { class: "muted" }, "ID do repositório: ", el("code", {}, id)));
}

async function tokensTab(workspace, repository) {
  const shown = el("div");
  const listing = el("div", { class: "panel" });
  const writePath = WRITE_TOKEN_PATHS[repository.format];
  async function refresh() {
    const lists = [["read", "Leitura", "/api/v1/personal-read-tokens/", (await when(api("GET", "/api/v1/personal-read-tokens?limit=100"))).tokens]];
    if (writePath) lists.push(["write", "Escrita", "/api/v1/" + writePath + "/", (await when(api("GET", "/api/v1/" + writePath + "?limit=100"))).tokens]);
    const rows = [];
    for (const [, label, path, tokens] of lists) {
      for (const t of tokens.filter((t) => t.repository_id === repository.repository_id)) {
        rows.push(el("tr", {}, el("td", {}, label), el("td", {}, formatDate(t.expires_at)), el("td", {}, t.revoked ? "revogado" : "ativo"),
          el("td", {}, t.revoked ? "" : el("button", { class: "danger", type: "button", onclick: async () => {
            await when(api("DELETE", path + t.token_id));
            await refresh();
          } }, "Revogar"))));
      }
    }
    listing.replaceChildren(table(["Tipo", "Expira", "Estado", ""], rows));
  }
  await refresh();
  const kinds = ["read"].concat(writePath ? ["write"] : []);
  return el("div", {}, shown, el("div", { class: "panel" }, el("h2", {}, "Novo token"), el("p", { class: "muted" }, "Precisa de grant no repositório e de MFA recente."), form("Gerar", [el("div", { class: "row" }, el("div", {}, field("Tipo", select("kind", kinds, "read"))), el("div", {}, field("Validade (dias, até 30)", input("days", { type: "number", min: "1", max: "30", value: "30" }))))], async (form) => {
    const path = form.get("kind") === "read" ? "personal-read-tokens" : writePath;
    const issued = await when(api("POST", "/api/v1/workspaces/" + workspace + "/repositories/" + repository.repository_id + "/" + path, { ttl_seconds: ttlSeconds(form.get("days")) }));
    shown.replaceChildren(secret("Token", issued.bearer));
    await refresh();
  })), listing);
}

async function grantsTab(workspace, repository) {
  const base = "/api/v1/workspaces/" + workspace + "/repositories/" + repository.repository_id + "/grants";
  let grants;
  try { grants = await api("GET", base + "?limit=100"); } catch (error) {
    return el("div", { class: "panel muted" }, error.status === 403 ? "Só owners e administradores do workspace gerenciam acesso." : error.message);
  }
  const members = await when(api("GET", "/api/v1/workspaces/" + workspace + "/members"));
  const names = Object.fromEntries(members.members.map((m) => [m.user_id, m.display_name]));
  const rows = grants.grants.map((g) => el("tr", {}, el("td", {}, names[g.user_id] || g.user_id), el("td", {}, g.role), el("td", {}, formatDate(g.granted_at)),
    el("td", {}, el("button", { class: "danger", type: "button", onclick: async () => {
      await when(api("DELETE", base + "/" + g.user_id + "/" + g.role));
      go("#/w/" + workspace + "/r/" + repository.repository_id + "/grants");
    } }, "Revogar"))));
  const people = members.members.map((m) => m.user_id);
  const label = (id) => (names[id] || id);
  const who = el("select", { name: "user", id: "user" }, people.map((id) => el("option", { value: id }, label(id))));
  return el("div", {}, el("div", { class: "panel" }, table(["Quem", "Papel", "Desde", ""], rows)),
    el("div", { class: "panel" }, el("h2", {}, "Conceder"), form("Conceder", [el("div", { class: "row" }, el("div", {}, field("Membro", who)), el("div", {}, field("Papel", select("role", ["reader", "publisher"], "reader"))))], async (form) => {
      await when(api("PUT", base + "/" + form.get("user") + "/" + form.get("role")));
      go("#/w/" + workspace + "/r/" + repository.repository_id + "/grants");
    })));
}

async function ciTab(workspace, repository) {
  const nodes = [];
  const accounts = await api("GET", "/api/v1/workspaces/" + workspace + "/service-accounts").catch(() => null);
  if (!accounts) return el("div", { class: "panel muted" }, "Só owners e administradores do workspace configuram CI.");
  const active = accounts.service_accounts.filter((a) => a.status === "active");
  const pick = () => el("select", { name: "account", id: "account" }, active.map((a) => el("option", { value: a.user_id }, a.description)));
  const shown = el("div");
  nodes.push(shown, el("div", { class: "panel" }, el("h2", {}, "Token estático de conta de serviço"), el("p", { class: "muted" }, "A conta precisa de grant neste repositório (aba Acesso)."), form("Gerar", [el("div", { class: "row" }, el("div", {}, field("Conta", pick())), el("div", {}, field("Tipo", select("kind", ["read", WRITE_KINDS[repository.format]], WRITE_KINDS[repository.format]))), el("div", {}, field("Dias", input("days", { type: "number", min: "1", max: "30", value: "30" }))))], async (form) => {
    const issued = await when(api("POST", "/api/v1/workspaces/" + workspace + "/service-accounts/" + form.get("account") + "/tokens", { repository_id: repository.repository_id, kind: form.get("kind"), ttl_seconds: ttlSeconds(form.get("days")) }));
    shown.replaceChildren(secret("Token da conta de serviço", issued.bearer));
  })));
  const publishersPath = "/api/v1/workspaces/" + workspace + "/repositories/" + repository.repository_id + "/trusted-publishers";
  const publishers = await api("GET", publishersPath).catch(() => null);
  if (publishers) {
    const rows = publishers.trusted_publishers.map((p) => el("tr", {}, el("td", {}, p.repository), el("td", {}, el("code", {}, p.ref)), el("td", {}, p.environment || "—"), el("td", {}, p.repository_id || "fixado no primeiro uso"),
      el("td", {}, el("button", { class: "danger", type: "button", onclick: async () => {
        await when(api("DELETE", publishersPath + "/" + p.publisher_id));
        go("#/w/" + workspace + "/r/" + repository.repository_id + "/ci");
      } }, "Revogar"))));
    nodes.push(el("div", { class: "panel" }, el("h2", {}, "GitHub Actions (sem segredo)"), table(["Repositório", "Ref", "Environment", "ID GitHub", ""], rows),
      form("Adicionar", [el("div", { class: "row" }, el("div", {}, field("Conta de serviço", pick())), el("div", {}, field("Repositório (dono/nome)", input("repository", { required: true }))), el("div", {}, field("Ref", input("ref", { required: true, value: "refs/heads/main" }))), el("div", {}, field("Environment (opcional)", input("environment"))))], async (form) => {
        await when(api("POST", publishersPath, { service_account_id: form.get("account"), repository: form.get("repository"), ref: form.get("ref"), environment: form.get("environment") || "" }));
        go("#/w/" + workspace + "/r/" + repository.repository_id + "/ci");
      }), el("p", { class: "muted" }, "No workflow: permissions id-token: write; troque o token OIDC (audiência " + location.origin + ") em POST /api/v1/trusted-publishing/github/exchange.")));
  }
  return el("div", {}, nodes);
}

async function reviewsTab(workspace, repository) {
  const base = "/api/v1/workspaces/" + workspace + "/repositories/" + repository.repository_id;
  const policy = await api("GET", base + "/oci-review-policy").catch(() => null);
  if (!policy) return el("div", { class: "panel muted" }, "Só owners e administradores do workspace revisam.");
  const reviews = await when(api("GET", base + "/oci-reviews"));
  const decide = (id, action) => async () => {
    await when(api("POST", base + "/oci-reviews/" + id + "/" + action));
    toast(action === "approve" ? "Aprovado e publicado." : "Rejeitado.");
    go("#/w/" + workspace + "/r/" + repository.repository_id + "/reviews");
  };
  const rows = reviews.reviews.map((r) => el("tr", {}, el("td", {}, r.image + (r.tag ? ":" + r.tag : "")), el("td", {}, el("code", {}, r.digest.slice(0, 19) + "…")), el("td", {}, formatDate(r.submitted_at)),
    el("td", {}, el("div", { class: "actions" }, el("button", { type: "button", onclick: decide(r.review_id, "approve") }, "Aprovar"), el("button", { class: "danger", type: "button", onclick: decide(r.review_id, "reject") }, "Rejeitar")))));
  return el("div", {}, el("div", { class: "panel" }, el("p", {}, "Revisão humana: ", policy.required ? "ligada" : "desligada"),
    el("button", { type: "button", class: "secondary", onclick: async () => {
      await when(api("PUT", base + "/oci-review-policy", { required: !policy.required, expected_revision: policy.revision }));
      go("#/w/" + workspace + "/r/" + repository.repository_id + "/reviews");
    } }, policy.required ? "Desligar" : "Ligar")), el("div", { class: "panel" }, el("p", { class: "muted" }, "Quem enviou não pode aprovar o próprio envio."), table(["Imagem", "Digest", "Enviado", ""], rows)));
}

async function accountPage() {
  const s = state.session;
  const passkeys = await when(api("GET", "/api/v1/auth/passkeys")).catch(() => ({ passkeys: [] }));
  const address = await api("GET", "/api/v1/account/email").catch(() => null);
  const rows = passkeys.passkeys.map((p) => el("tr", {}, el("td", {}, p.name), el("td", {}, formatDate(p.created_at)), el("td", {}, formatDate(p.last_used_at) || "nunca"),
    el("td", {}, el("button", { class: "danger", type: "button", onclick: async () => {
      if (!confirm("Remover a passkey " + p.name + "?")) return;
      await when(api("DELETE", "/api/v1/auth/passkeys/" + encodeURIComponent(p.passkey_id)));
      go("#/account");
    } }, "Remover"))));
  const totp = el("div");
  if (!s.has_totp && s.level === "standard") {
    totp.append(el("button", { type: "button", class: "secondary", onclick: async () => {
      const started = await when(api("POST", "/api/v1/auth/mfa/enrollment/start"));
      totp.replaceChildren(el("p", { class: "muted" }, "Adicione ao autenticador:"), el("code", { class: "secret" }, started.secret), form("Confirmar", [field("Código", input("code", { required: true }))], async (form) => {
        const done = await when(api("POST", "/api/v1/auth/mfa/enrollment/complete", { code: form.get("code") }));
        await loadSession();
        totp.replaceChildren(secret("Códigos de recuperação", done.recovery_codes.join("  ")));
      }));
    } }, "Cadastrar TOTP"));
  }
  return el("div", {}, el("h1", {}, "Conta"),
    el("div", { class: "panel" }, el("p", {}, el("strong", {}, s.display_name || ""), " ", s.login_name ? el("code", {}, s.login_name) : ""), el("p", { class: "muted" }, "TOTP: ", s.has_totp ? "cadastrado" : "não cadastrado", " · sessão: ", s.level, s.mfa_recent ? " (MFA recente)" : ""), totp),
    address ? emailPanel(address) : "",
    el("div", { class: "panel" }, el("h2", {}, "Passkeys"), table(["Nome", "Criada", "Último uso", ""], rows),
      state.methods && state.methods.passkeys && window.PublicKeyCredential ? form("Adicionar passkey", [field("Nome", input("name", { required: true, value: "Este dispositivo" }))], async (form) => {
        await passkeyRegister(form.get("name"));
        await loadSession();
        go("#/account");
      }) : el("p", { class: "muted" }, "Passkeys indisponíveis neste navegador ou nesta instalação.")));
}

function emailPanel(address) {
  const status = address.email ? [el("code", {}, address.email), " ", address.verified ? el("span", { class: "badge" }, "confirmado") : el("span", { class: "badge" }, "não confirmado")] : [el("span", { class: "muted" }, "nenhum")];
  const pending = address.pending_email ? el("p", { class: "muted" }, "Aguardando confirmação: ", el("code", {}, address.pending_email), ". Abra o link enviado para esse endereço.") : "";
  const change = address.delivery_enabled ? form("Enviar confirmação", [field("Novo e-mail", input("email", { type: "email", required: true, autocomplete: "email" }))], async (form) => {
    await when(api("PUT", "/api/v1/account/email", { email: form.get("email") }));
    toast("Enviamos um link de confirmação. O endereço só passa a valer depois de confirmado.");
    go("#/account");
  }) : el("p", { class: "muted" }, "O envio de e-mail não está configurado nesta instalação.");
  return el("div", { class: "panel" }, el("h2", {}, "E-mail"), el("p", {}, "Atual: ", status), el("p", { class: "muted" }, "Um e-mail confirmado permite pedir a recuperação da senha e receber avisos de segurança."), pending, change);
}

const EMAIL_HEALTH = { ok: "funcionando", failing: "há e-mails que não foram entregues", stalled: "há e-mails parados na fila há mais de 30 minutos" };
const EMAIL_TEMPLATES = { "registry.workspace-invitation": "convite", "registry.account-recovery": "recuperação", "registry.email-verification": "confirmação de e-mail", "registry.security-notice": "aviso de segurança" };

function emailAdminPanel(mail) {
  if (!mail.enabled) return el("div", { class: "panel" }, el("h2", {}, "E-mail"), el("p", { class: "muted" }, "Desligado. Links são entregues à mão."));
  const rows = mail.failures.map((f) => el("tr", {}, el("td", {}, EMAIL_TEMPLATES[f.template] || f.template), el("td", {}, f.recipient), el("td", {}, el("code", {}, f.error)), el("td", {}, String(f.attempts)), el("td", {}, formatDate(f.failed_at)),
    el("td", {}, el("button", { type: "button", class: "secondary", onclick: async () => {
      await when(api("POST", "/api/v1/admin/email/failures/" + encodeURIComponent(f.job_id) + "/resend"));
      toast("Reenvio na fila.");
      await refreshEmailAlert();
      go("#/admin");
    } }, "Reenviar"))));
  return el("div", { class: "panel" }, el("h2", {}, "E-mail"),
    el("p", {}, "Provedor ", el("code", {}, mail.provider), " · ", el("span", { class: mail.health === "ok" ? "badge" : "badge alert" }, EMAIL_HEALTH[mail.health] || mail.health), " · na fila: ", String(mail.pending), mail.oldest_pending_at ? " (mais antigo de " + formatDate(mail.oldest_pending_at) + ")" : ""),
    mail.failures.length ? [el("p", { class: "muted" }, "Corrija a causa (template, remetente, chave) antes de reenviar. Links de recuperação e confirmação podem ter expirado: nesse caso, gere um novo."), table(["Tipo", "Para", "Erro", "Tentativas", "Quando", ""], rows)] : el("p", { class: "muted" }, "Nenhuma falha."));
}

async function adminPage() {
  const policy = await when(api("GET", "/api/v1/admin/signup-policy"));
  const replication = await api("GET", "/api/v1/admin/replication").catch(() => null);
  const mail = await api("GET", "/api/v1/admin/email").catch(() => null);
  const recovery = el("div");
  return el("div", {}, el("h1", {}, "Administração"),
    el("div", { class: "panel" }, el("h2", {}, "Cadastro"), el("p", {}, "Política atual: ", el("code", {}, policy.policy)),
      el("button", { type: "button", class: "secondary", onclick: async () => {
        await when(api("PUT", "/api/v1/admin/signup-policy", { policy: policy.policy === "closed" ? "invitations" : "closed" }));
        go("#/admin");
      } }, policy.policy === "closed" ? "Permitir cadastro por convite" : "Fechar cadastro")),
    replication ? el("div", { class: "panel" }, el("h2", {}, "Replicação do banco"), replication.enabled ? el("p", {}, "Estado: ", el("strong", {}, replication.health), " · atraso ", String(replication.lag_seconds || 0), " s · último envio ", formatDate(replication.last_synced_at) || "—") : el("p", { class: "muted" }, "Desligada.")) : "",
    mail ? emailAdminPanel(mail) : "",
    el("div", { class: "panel" }, el("h2", {}, "Recuperar uma conta"), recovery, form("Gerar link", [el("div", { class: "row" }, el("div", {}, field("ID do usuário", input("user", { required: true }))), el("div", {}, el("label", {}, input("reset_mfa", { type: "checkbox" }), " remover TOTP e passkeys")),
      state.methods && state.methods.email_recovery ? el("div", {}, el("label", {}, input("send_email", { type: "checkbox" }), " enviar ao e-mail confirmado da pessoa")) : "")], async (form) => {
      const issued = await when(api("POST", "/api/v1/admin/users/" + encodeURIComponent(form.get("user")) + "/recovery", { reset_mfa: form.get("reset_mfa") === "on", send_email: form.get("send_email") === "on" }));
      if (issued.emailed) {
        recovery.replaceChildren(el("p", {}, "Link enviado ao e-mail confirmado da pessoa. Vale uma vez, por 24 horas."));
        return;
      }
      recovery.replaceChildren(secret("Link de recuperação", location.origin + "/#/recover?token=" + encodeURIComponent(issued.token), "Entregue à pessoa por um canal seu. Vale uma vez, por 24 horas."));
    })));
}

function invitePage(params) {
  const token = params.get("token") || "";
  const root = el("div", { class: "narrow" });
  const signedIn = state.session && (state.session.level === "standard" || state.session.level === "mfa");
  if (signedIn) {
    root.append(el("div", { class: "panel" }, el("h1", {}, "Convite"), el("p", {}, "Entrar no workspace com a conta atual?"), el("button", { type: "button", onclick: async () => {
      const joined = await when(api("POST", "/api/v1/invitations/accept", { token }));
      go("#/w/" + joined.workspace_id);
    } }, "Aceitar")));
    return root;
  }
  root.append(el("div", { class: "panel" }, el("h1", {}, "Criar conta"), form("Criar conta", [field("Login", input("login_name", { required: true, autocomplete: "username" })), field("Nome", input("display_name", { required: true })), field("Senha (15+ caracteres)", input("password", { type: "password", required: true, minlength: "15", autocomplete: "new-password" }))], async (form) => {
    await when(api("POST", "/api/v1/auth/invitations/redeem", { token, login_name: form.get("login_name"), display_name: form.get("display_name"), password: form.get("password") }));
    toast("Conta criada. Entre com seu login.");
    go("#/login");
  }), el("p", { class: "muted" }, "Já tem conta? ", el("a", { href: "#/login" }, "Entre"), " e abra o link de novo.")));
  return root;
}

function recoverPage(params) {
  const token = params.get("token") || "";
  return el("div", { class: "narrow" }, el("div", { class: "panel" }, el("h1", {}, "Recuperar acesso"), form("Definir", [field("Nova senha (15+ caracteres; deixe vazio se sua conta entra pelo Muira)", input("password", { type: "password", autocomplete: "new-password" }))], async (form) => {
    await when(api("POST", "/api/v1/auth/recovery", { token, password: form.get("password") || "" }));
    toast("Pronto. Entre de novo.");
    go("#/login");
  })));
}

function forgotPage() {
  const root = el("div", { class: "narrow" });
  const panel = el("div", { class: "panel" }, el("h1", {}, "Esqueci minha senha"), el("p", { class: "muted" }, "Informe seu login. Se a conta tiver e-mail confirmado, enviamos um link que vale por uma hora."),
    form("Enviar link", [field("Login", input("login_name", { required: true, autocomplete: "username" }))], async (form) => {
      await when(api("POST", "/api/v1/auth/recovery/request", { login_name: form.get("login_name") }));
      panel.replaceChildren(el("h1", {}, "Verifique seu e-mail"), el("p", {}, "Se a conta existir e tiver e-mail confirmado, o link chega em instantes. O segundo fator continua sendo pedido ao entrar."), el("p", {}, el("a", { href: "#/login" }, "Voltar")));
    }), el("p", { class: "muted" }, "Sem e-mail confirmado? Peça a um administrador do registry."));
  root.append(panel);
  return root;
}

// The address is confirmed only on click: mail scanners that open links
// cannot confirm it.
function verifyEmailPage(params) {
  const token = params.get("token") || "";
  const panel = el("div", { class: "panel" }, el("h1", {}, "Confirmar e-mail"), el("p", {}, "Confirmar que este endereço é seu?"), el("button", { type: "button", onclick: async () => {
    await when(api("POST", "/api/v1/auth/email/confirm", { token }));
    panel.replaceChildren(el("h1", {}, "E-mail confirmado"), el("p", {}, el("a", { href: "#/" }, "Continuar")));
  } }, "Confirmar"));
  return el("div", { class: "narrow" }, panel);
}

// ---------- router ----------

async function render() {
  const [path, query] = (location.hash.slice(1) || "/").split("?");
  const params = new URLSearchParams(query || "");
  const parts = path.split("/").filter(Boolean);
  if (!state.methods) state.methods = await api("GET", "/api/v1/auth/methods").catch(() => ({ passkeys: false, muira: false }));
  if (state.session === null) await loadSession();
  const signedIn = state.session && (state.session.level === "standard" || state.session.level === "mfa");
  let page;
  try {
    if (parts[0] === "invite") page = invitePage(params);
    else if (parts[0] === "recover") page = recoverPage(params);
    else if (parts[0] === "verify-email") page = verifyEmailPage(params);
    else if (parts[0] === "forgot" && !signedIn) page = forgotPage();
    else if (!signedIn || parts[0] === "login") page = loginPage(params);
    else if (parts[0] === "account") page = await accountPage();
    else if (parts[0] === "admin") page = await adminPage();
    else if (parts[0] === "w" && parts[2] === "r") page = await repositoryPage(parts[1], parts[3], parts[4]);
    else if (parts[0] === "w") page = await workspacePage(parts[1], parts[2]);
    else page = await workspacesPage();
  } catch (error) {
    page = el("div", { class: "panel error" }, error.message);
  }
  app.replaceChildren(page);
}

window.addEventListener("hashchange", render);
render();
