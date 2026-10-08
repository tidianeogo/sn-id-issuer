// Interface d'enrôlement : connexion Keycloak (code + PKCE S256, client public), puis API /admin/* de l'issuer.
"use strict";
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const store = {               // sessionStorage peut être indisponible (navigation privée) : repli en mémoire
    mem: {},
    get(k) { try { return sessionStorage.getItem(k); } catch { return this.mem[k] ?? null; } },
    set(k, v) { try { sessionStorage.setItem(k, v); } catch { this.mem[k] = v; } },
    del(k) { try { sessionStorage.removeItem(k); } catch { delete this.mem[k]; } },
  };
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const rand = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));
  const claimsOf = (jwt) => JSON.parse(decodeURIComponent(escape(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")))));
  const frDate = (iso) => (iso ? iso.split("-").reverse().join("/") : "");

  // silhouette affichée tant qu'aucune photo n'est choisie
  const NO_PHOTO = "data:image/svg+xml," + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 120"><rect width="96" height="120" fill="#e3e8e5"/><circle cx="48" cy="44" r="20" fill="#b9c4bf"/><path d="M14 120c2-26 16-38 34-38s32 12 34 38z" fill="#b9c4bf"/></svg>');
  let cfg, tokens = null, citizens = [], editing = null, photoB64 = null;
  const redirectUri = location.origin + "/admin/";

  // ------------------------------------------------------------------ OIDC
  async function login() {
    const verifier = rand(48), state = rand(16);
    const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
    store.set("pkce", JSON.stringify({ verifier, state }));
    const q = new URLSearchParams({ client_id: cfg.client_id, response_type: "code", scope: "openid",
      redirect_uri: redirectUri, state, code_challenge: challenge, code_challenge_method: "S256" });
    location.assign(`${cfg.authority}/protocol/openid-connect/auth?${q}`);
  }

  async function tokenRequest(params) {
    const r = await fetch(`${cfg.authority}/protocol/openid-connect/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: cfg.client_id, ...params }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error_description || j.error || `HTTP ${r.status}`);
    return { ...j, obtained: Date.now() };
  }

  async function handleCallback() {
    const q = new URLSearchParams(location.search);
    if (!q.has("code") && !q.has("error")) return;
    history.replaceState(null, "", redirectUri);
    if (q.has("error")) throw new Error(q.get("error_description") || q.get("error"));
    const saved = JSON.parse(store.get("pkce") || "{}");
    store.del("pkce");
    if (!saved.state || saved.state !== q.get("state")) throw new Error("Réponse de connexion inattendue (state)");
    tokens = await tokenRequest({ grant_type: "authorization_code", code: q.get("code"),
      redirect_uri: redirectUri, code_verifier: saved.verifier });
    store.set("tokens", JSON.stringify(tokens));
  }

  async function accessToken() {
    if (!tokens) return null;
    if (Date.now() < tokens.obtained + (tokens.expires_in - 30) * 1000) return tokens.access_token;
    try {
      tokens = await tokenRequest({ grant_type: "refresh_token", refresh_token: tokens.refresh_token });
      store.set("tokens", JSON.stringify(tokens));
      return tokens.access_token;
    } catch { logoutLocal(); return null; }
  }

  function logoutLocal() { tokens = null; store.del("tokens"); showLogin(); }

  function logout() {
    const idt = tokens && tokens.id_token;
    store.del("tokens");
    const q = new URLSearchParams({ client_id: cfg.client_id, post_logout_redirect_uri: redirectUri });
    if (idt) q.set("id_token_hint", idt);
    location.assign(`${cfg.authority}/protocol/openid-connect/logout?${q}`);
  }

  async function api(method, path, body) {
    const t = await accessToken();
    if (!t) throw new Error("Session expirée : reconnectez-vous");
    const r = await fetch(path, { method, headers: { Authorization: `Bearer ${t}`,
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined });
    if (r.status === 401) { logoutLocal(); throw new Error("Session expirée : reconnectez-vous"); }
    const ct = r.headers.get("content-type") || "";
    const data = ct.includes("json") ? await r.json() : await r.blob();
    if (!r.ok) {
      const e = new Error((data && (data.error_description || (Array.isArray(data.detail) ? pydanticMsg(data.detail) : data.detail))) || `HTTP ${r.status}`);
      e.fields = (data && data.fields) || pydanticFields(data && data.detail);
      e.status = r.status;
      throw e;
    }
    return data;
  }
  const pydanticMsg = (d) => "Champs invalides : " + d.map((x) => `${x.loc.slice(-1)[0]} (${x.msg})`).join(", ");
  const pydanticFields = (d) => Array.isArray(d) ? Object.fromEntries(d.map((x) => [String(x.loc.slice(-1)[0]), x.msg])) : {};

  // ------------------------------------------------------------------ écrans
  function showLogin(msg) {
    $("#app").classList.add("hidden"); $("#logout").classList.add("hidden"); $("#who").textContent = "";
    $("#login-panel").classList.remove("hidden");
    $("#login-msg").innerHTML = msg ? `<div class="msg err">${esc(msg)}</div>` : "";
  }

  function showApp() {
    const c = claimsOf(tokens.access_token);
    const roles = (c.realm_access && c.realm_access.roles) || [];
    if (!roles.includes(cfg.admin_role)) {
      showLogin(`Le compte « ${c.preferred_username} » n'a pas le rôle ${cfg.admin_role}.`);
      $("#logout").classList.remove("hidden");
      return;
    }
    $("#who").textContent = c.preferred_username;
    $("#login-panel").classList.add("hidden");
    $("#app").classList.remove("hidden"); $("#logout").classList.remove("hidden");
    loadList();
  }

  // ------------------------------------------------------------------ liste
  async function loadList() {
    try {
      citizens = await api("GET", "/admin/citizens");
      $("#list-msg").innerHTML = "";
      renderList();
    } catch (e) { $("#list-msg").innerHTML = `<div class="msg err">${esc(e.message)}</div>`; }
  }

  const statusBadge = (s) => ({ ACTIVE: '<span class="badge ok">active</span>', SUSPENDED: '<span class="badge warn">suspendue</span>',
    DECEASED: '<span class="badge err">décédé(e)</span>', LOST: '<span class="badge warn">perdue</span>',
    REVOKED: '<span class="badge err">révoquée</span>' }[s] || `<span class="badge">${esc(s)}</span>`);

  function renderList() {
    const q = $("#search").value.trim().toUpperCase().replace(/\s+/g, "");
    const rows = citizens.filter((c) => !q || (c.family_name + c.given_name + c.nin + c.cards.map((k) => k.card_number).join(""))
      .toUpperCase().replace(/\s+/g, "").includes(q));
    if (!rows.length) { $("#rows").innerHTML = `<tr><td colspan="6">Aucun titulaire${q ? " pour cette recherche" : ""}.</td></tr>`; return; }
    const today = new Date().toISOString().slice(0, 10);
    $("#rows").innerHTML = rows.map((c) => {
      const card = c.cards[0] || {};
      const expired = card.date_of_expiry && card.date_of_expiry < today;
      const acc = c.account === undefined || c.account === null ? '<span class="badge">?</span>'
        : !c.account.exists ? '<span class="badge warn">aucun</span>'
        : c.account.enabled ? '<span class="badge ok">actif</span>' : '<span class="badge err">désactivé</span>';
      return `<tr data-nin="${esc(c.nin)}">
        <td><b>${esc(c.family_name)}</b> ${esc(c.given_name)}<div class="sub">${frDate(c.date_of_birth)} · ${esc(c.sex)}${c.has_photo ? "" : " · sans photo"}</div></td>
        <td>${esc(c.nin_display)}<div class="sub">${esc(card.card_number_display || "")}</div></td>
        <td class="hide-sm">${frDate(card.date_of_expiry)}${expired ? ' <span class="badge err">expirée</span>' : ""}</td>
        <td>${statusBadge(c.status)}${card.status && card.status !== "ACTIVE" ? "<br>carte " + statusBadge(card.status) : ""}</td>
        <td>${acc}</td>
        <td><div class="actions">
          <button class="small" data-act="edit">Modifier</button>
          <button class="small" data-act="password">${c.account && !c.account.exists ? "Créer le compte" : "Nouveau mot de passe"}</button>
          <button class="small" data-act="status">${c.status === "ACTIVE" ? "Suspendre" : "Réactiver"}</button>
          ${card.status === "ACTIVE" ? '<button class="small" data-act="lost">Carte perdue</button>' : card.card_number ? '<button class="small" data-act="cardok">Carte valide</button>' : ""}
        </div></td></tr>`;
    }).join("");
  }

  async function rowAction(ev) {
    const b = ev.target.closest("button[data-act]"); if (!b) return;
    const nin = b.closest("tr").dataset.nin, c = citizens.find((x) => x.nin === nin), card = c.cards[0];
    const name = `${c.given_name} ${c.family_name}`;
    b.disabled = true;
    try {
      if (b.dataset.act === "edit") return openForm(c);
      if (b.dataset.act === "password") {
        if (!confirm(`Générer un nouveau mot de passe temporaire pour ${name} ?`)) return;
        showAccount(c, await api("POST", `/admin/citizens/${nin}/account`), "Compte du titulaire");
      } else if (b.dataset.act === "status") {
        const to = c.status === "ACTIVE" ? "SUSPENDED" : "ACTIVE";
        if (!confirm(`${to === "SUSPENDED" ? "Suspendre" : "Réactiver"} ${name} ? ${to === "SUSPENDED" ? "Son compte est désactivé et aucun VC ne lui sera plus émis." : ""}`)) return;
        await api("PATCH", `/admin/citizens/${nin}`, { status: to });
      } else if (b.dataset.act === "lost" || b.dataset.act === "cardok") {
        const to = b.dataset.act === "lost" ? "LOST" : "ACTIVE";
        if (!confirm(`Marquer la carte ${card.card_number_display} comme ${to === "LOST" ? "perdue" : "valide"} ?`)) return;
        await api("PATCH", `/admin/cards/${card.card_number}`, { status: to });
      }
      await loadList();
    } catch (e) { $("#list-msg").innerHTML = `<div class="msg err">${esc(e.message)}</div>`; }
    finally { b.disabled = false; }
  }

  // ------------------------------------------------------------------ formulaire
  const F = () => $("#form");
  const field = (n) => F().elements[n];
  const ELECTORAL = ["voter_number", "region", "department", "arrondissement", "commune", "polling_place", "polling_station"];

  function clearFieldErrors() {
    $$("[data-f]", F()).forEach((l) => { l.classList.remove("invalid"); const e = $(".fielderr", l); if (e) e.textContent = ""; });
    $("#form-msg").innerHTML = "";
  }
  function showFieldErrors(fields) {
    for (const [k, v] of Object.entries(fields || {})) {
      const l = $(`[data-f="${k}"]`, F()); if (!l) continue;
      l.classList.add("invalid"); const e = $(".fielderr", l); if (e) e.textContent = v;
    }
  }

  async function openForm(c) {
    editing = c || null; photoB64 = null;
    F().reset(); clearFieldErrors(); resetScan();
    $("#photo-preview").src = NO_PHOTO;
    $("#form-title").textContent = c ? `Modifier : ${c.given_name} ${c.family_name}` : "Nouvelle carte";
    $("#result-panel").classList.add("hidden");
    $("#form-panel").classList.remove("hidden");
    if (c) {
      const card = c.cards[0] || {};
      for (const k of ["given_name", "family_name", "date_of_birth", "place_of_birth", "sex", "height_cm", "address"]) field(k).value = c[k] ?? "";
      field("nin").value = c.nin_display;
      field("card_number").value = card.card_number_display || "";
      for (const k of ["date_of_issue", "date_of_expiry", "registration_center"]) field(k).value = card[k] ?? "";
      field("mrz").value = (card.mrz || []).join("\n");
      for (const k of ELECTORAL) field(k).value = (c.electoral && c.electoral[k]) || "";
      field("create_account").checked = !(c.account && c.account.exists);
      if (c.has_photo) {
        try { $("#photo-preview").src = URL.createObjectURL(await api("GET", `/admin/citizens/${c.nin}/photo`)); } catch { /* sans photo */ }
      }
    }
    $("#form-panel").scrollIntoView({ behavior: "smooth", block: "start" });
    field("mrz").focus({ preventScroll: true });
  }

  function mrzLines() {
    return field("mrz").value.toUpperCase().split(/\r?\n/).map((l) => l.replace(/\s+/g, "")).filter(Boolean);
  }

  async function readMrz() {
    clearFieldErrors();
    try {
      const m = await api("POST", "/admin/mrz/parse", { mrz: mrzLines() });
      field("mrz").value = m.lines.join("\n");
      field("card_number").value = m.card_number_display;
      field("family_name").value = m.family_name;
      field("given_name").value = m.given_name;
      field("sex").value = m.sex;
      field("date_of_birth").value = m.date_of_birth;
      field("date_of_expiry").value = m.date_of_expiry;
      const msgs = [`MRZ valide (${m.issuing_state}) : champs pré-remplis. Complétez le reste depuis la carte.`];
      if (m.issuing_state !== "SEN") msgs.push(`Attention : pays émetteur ${m.issuing_state}, seules les cartes du Sénégal sont acceptées.`);
      $("#form-msg").innerHTML = `<div class="msg ${m.issuing_state === "SEN" ? "ok" : "warn"}">${msgs.map(esc).join("<br>")}</div>`;
    } catch (e) {
      showFieldErrors({ mrz: e.message });
      $("#form-msg").innerHTML = `<div class="msg err">${esc(e.message)}</div>`;
    }
  }

  function payload() {
    const v = (n) => field(n).value.trim();
    const p = {
      nin: v("nin"), card_number: v("card_number"), given_name: v("given_name"), family_name: v("family_name"),
      date_of_birth: v("date_of_birth") || null, place_of_birth: v("place_of_birth") || null, sex: v("sex"),
      height_cm: v("height_cm") ? Number(v("height_cm")) : null, address: v("address") || null,
      date_of_issue: v("date_of_issue") || null, date_of_expiry: v("date_of_expiry") || null,
      registration_center: v("registration_center") || null, mrz: mrzLines(),
      create_account: field("create_account").checked,
    };
    if (v("voter_number")) p.electoral = Object.fromEntries(ELECTORAL.map((k) => [k, v(k) || null]));
    if (photoB64) p.photo_jpeg_base64 = photoB64;
    return p;
  }

  function localErrors(p) {
    const e = {};
    for (const k of ["nin", "card_number", "given_name", "family_name", "date_of_birth", "sex", "date_of_issue", "date_of_expiry"])
      if (!p[k]) e[k] = "obligatoire";
    if (p.mrz.length !== 3) e.mrz = "3 lignes attendues";
    return e;
  }

  async function check(save) {
    clearFieldErrors();
    const p = payload();
    const le = localErrors(p);
    if (Object.keys(le).length) {
      showFieldErrors(le);
      $("#form-msg").innerHTML = `<div class="msg err">Complétez les champs obligatoires.</div>`;
      return;
    }
    const btn = save ? $("#save") : $("#check"); btn.disabled = true;
    try {
      const v = await api("POST", "/admin/citizens/validate", p);
      showFieldErrors(v.errors);
      const warn = v.warnings.length ? `<div class="msg warn">À vérifier :<ul>${v.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul></div>` : "";
      if (!v.valid) {
        $("#form-msg").innerHTML = `<div class="msg err">Corrigez les champs signalés :<ul>${Object.entries(v.errors).map(([k, m]) => `<li>${esc(k)} : ${esc(m)}</li>`).join("")}</ul></div>` + warn;
        return;
      }
      if (!save) {
        $("#form-msg").innerHTML = `<div class="msg ok">Tout est cohérent (MRZ, recto, verso)${v.existing_citizen ? " — ce NIN existe déjà : ses données seront mises à jour" : ""}.</div>` + warn;
        return;
      }
      if (v.warnings.length && !confirm("Des points sont à vérifier :\n- " + v.warnings.join("\n- ") + "\n\nEnregistrer quand même ?")) {
        $("#form-msg").innerHTML = warn; return;
      }
      const r = await api("PUT", "/admin/citizens", p);
      $("#form-panel").classList.add("hidden");
      showAccount(r, r.account, r.created ? "Carte enregistrée" : "Titulaire mis à jour");
      await loadList();
    } catch (e) {
      showFieldErrors(e.fields);
      $("#form-msg").innerHTML = `<div class="msg err">${esc(e.message)}</div>`;
    } finally { btn.disabled = false; }
  }

  function showAccount(c, acc, title) {
    $("#result-title").textContent = title;
    let html = `<p><b>${esc(c.given_name)} ${esc(c.family_name)}</b> — NIN ${esc(c.nin_display || c.nin)}</p>`;
    if (!acc) html += `<p>Aucun compte de connexion n'a été modifié.</p>`;
    else if (acc.error) html += `<div class="msg err">Compte Keycloak non créé : ${esc(acc.error)}</div>`;
    else if (acc.temporary_password) {
      html += `<p>Identifiant de connexion : <b>${esc(acc.username)}</b><br>Mot de passe temporaire (affiché une seule fois) :</p>
        <p><span class="secret" id="pwd">${esc(acc.temporary_password)}</span> <button class="small" id="copy">Copier</button></p>
        <p>Remettez-le au titulaire : il devra le changer à sa première connexion dans Inji Wallet.</p>`;
    } else html += `<p>Compte existant (<b>${esc(acc.username)}</b>) : mot de passe inchangé.</p>`;
    html += `<p>Pour obtenir sa carte numérique : Inji Wallet → <b>+</b>, ou scanner le QR de <a href="${esc(cfg.offer_url)}" target="_blank" rel="noopener">${esc(cfg.offer_url)}</a>.</p>`;
    $("#result").innerHTML = html;
    $("#result-panel").classList.remove("hidden");
    const cp = $("#copy");
    if (cp) cp.onclick = () => navigator.clipboard.writeText(acc.temporary_password).then(() => { cp.textContent = "Copié"; }, () => {});
    $("#result-panel").scrollIntoView({ behavior: "smooth" });
  }

  // Photo : recadrage 3:4 centré, 240×320 max, JPEG ≤ 55 Ko (embarquée dans le VC)
  async function onPhoto(ev) {
    const file = ev.target.files[0]; if (!file) return;
    const img = new Image();
    img.src = URL.createObjectURL(file);
    try { await img.decode(); } catch { showFieldErrors({ photo: "image illisible" }); return; }
    const ratio = 3 / 4;
    let sw = img.naturalWidth, sh = img.naturalHeight, sx = 0, sy = 0;
    if (sw / sh > ratio) { const w = sh * ratio; sx = (sw - w) / 2; sw = w; } else { const h = sw / ratio; sy = (sh - h) / 4; sh = h; }
    const W = Math.min(240, Math.round(sw)), H = Math.round(W / ratio);
    const cv = document.createElement("canvas"); cv.width = W; cv.height = H;
    cv.getContext("2d").drawImage(img, sx, sy, sw, sh, 0, 0, W, H);
    let q = 0.85, url;
    do { url = cv.toDataURL("image/jpeg", q); q -= 0.1; } while (url.length * 0.75 > 55000 && q > 0.3);
    photoB64 = url.split(",")[1];
    $("#photo-preview").src = url;
  }

  // ------------------------------------------------------------------ lecture automatique (OCR) recto / verso
  const scans = { recto: null, verso: null };
  const SOURCE_TAG = { mrz: ["mrz", "MRZ ✓"], ocr: ["ocr", "lu"], "déduit": ["deduit", "déduit"] };

  function clearOcrMarks() {
    $$(".ocr-filled", F()).forEach((l) => l.classList.remove("ocr-filled"));
    $$(".src", F()).forEach((t) => t.remove());
  }
  function resetScan() {
    scans.recto = scans.verso = null;
    for (const side of ["recto", "verso"]) {
      const d = $(`#drop-${side}`); d.classList.remove("has");
      const im = $("img", d); if (im) im.remove();
      $(`#scan-${side}`).value = "";
    }
    $("#ocr").disabled = true; $("#ocr-msg").innerHTML = "";
    clearOcrMarks();
  }

  // Réduit la photo (≤ 2000 px, JPEG) avant envoi : upload plus rapide, précision OCR conservée
  async function shrink(file) {
    const img = new Image();
    img.src = URL.createObjectURL(file);
    await img.decode();
    const k = Math.min(1, 2000 / Math.max(img.naturalWidth, img.naturalHeight));
    const cv = document.createElement("canvas");
    cv.width = Math.round(img.naturalWidth * k); cv.height = Math.round(img.naturalHeight * k);
    cv.getContext("2d").drawImage(img, 0, 0, cv.width, cv.height);
    const blob = await new Promise((res) => cv.toBlob(res, "image/jpeg", 0.92));
    return { blob, url: URL.createObjectURL(blob) };
  }

  async function setScan(side, file) {
    if (!file || !file.type.startsWith("image/")) return;
    const d = $(`#drop-${side}`);
    try {
      const { blob, url } = await shrink(file);
      scans[side] = blob;
      let im = $("img", d); if (!im) { im = document.createElement("img"); d.insertBefore(im, d.firstChild); }
      im.src = url; im.alt = side;
      d.classList.add("has");
    } catch { $("#ocr-msg").innerHTML = `<div class="msg err">Image du ${side} illisible.</div>`; }
    $("#ocr").disabled = !(scans.recto && scans.verso);
  }

  function bindDrop(side) {
    const d = $(`#drop-${side}`), input = $(`#scan-${side}`);
    input.onchange = () => setScan(side, input.files[0]);
    d.ondragover = (e) => { e.preventDefault(); d.classList.add("over"); };
    d.ondragleave = () => d.classList.remove("over");
    d.ondrop = (e) => { e.preventDefault(); d.classList.remove("over"); setScan(side, e.dataTransfer.files[0]); };
  }

  function markField(name, source) {
    const el = field(name); if (!el) return;
    const l = el.closest("label"); if (!l) return;
    l.classList.add("ocr-filled");
    const [cls, txt] = SOURCE_TAG[source] || ["ocr", source];
    const head = $("span", l);
    if (head && !$(".src", head)) head.insertAdjacentHTML("beforeend", `<span class="src ${cls}">${txt}</span>`);
    el.addEventListener("input", () => { l.classList.remove("ocr-filled"); const t = $(".src", l); if (t) t.remove(); }, { once: true });
  }

  async function runOcr() {
    const btn = $("#ocr"); btn.disabled = true;
    const old = btn.textContent; btn.innerHTML = '<span class="spinner"></span> Lecture en cours…';
    clearFieldErrors(); clearOcrMarks();
    $("#ocr-msg").innerHTML = "";
    try {
      const t = await accessToken();
      if (!t) throw new Error("Session expirée : reconnectez-vous");
      const fd = new FormData();
      fd.append("recto", scans.recto, "recto.jpg");
      fd.append("verso", scans.verso, "verso.jpg");
      const r = await fetch("/admin/ocr", { method: "POST", headers: { Authorization: `Bearer ${t}` }, body: fd });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data.error_description || data.detail || `HTTP ${r.status}`);
      fillFromOcr(data);
    } catch (e) {
      $("#ocr-msg").innerHTML = `<div class="msg err">${esc(e.message)}</div>`;
    } finally { btn.textContent = old; btn.disabled = !(scans.recto && scans.verso); }
  }

  function fillFromOcr(data) {
    const v = data.values || {};
    const set = (name, value) => { if (value !== undefined && value !== null && field(name)) field(name).value = value; };
    for (const k of ["card_number", "family_name", "given_name", "sex", "date_of_birth", "date_of_expiry", "date_of_issue",
                     "place_of_birth", "height_cm", "registration_center", "address", "nin", "mrz", ...ELECTORAL]) {
      if (v[k] === undefined) continue;
      set(k, v[k]);
      markField(k, data.fields[k].source);
    }
    if (data.photo_jpeg_base64) {
      photoB64 = data.photo_jpeg_base64;
      $("#photo-preview").src = "data:image/jpeg;base64," + photoB64;
      const l = $('[data-f="photo"]', F()); if (l) l.classList.add("ocr-filled");
    }
    const n = Object.keys(v).filter((k) => k !== "nationality").length;
    const parts = [`${n} champs lus en ${(data.duration_ms / 1000).toFixed(1)} s — MRZ ${data.mrz.valid ? "valide (chiffres de contrôle vérifiés)" : "non validée"}.`];
    if (data.photo_jpeg_base64) parts.push(`Photo extraite (${data.photo_source === "visage" ? "visage détecté" : "zone photo"}).`);
    parts.push("Champs surlignés : à vérifier sur la carte avant d'enregistrer.");
    const labels = { card_number: "n° de carte", given_name: "prénoms", family_name: "nom", date_of_birth: "date de naissance",
      sex: "sexe", date_of_issue: "date de délivrance", date_of_expiry: "date d'expiration", nin: "NIN", mrz: "MRZ" };
    let html = `<div class="msg ${data.mrz.valid && !data.missing.length ? "ok" : "warn"}">${parts.map(esc).join("<br>")}</div>`;
    if (data.missing.length) html += `<div class="msg err">Non lus, à saisir : ${data.missing.map((m) => esc(labels[m] || m)).join(", ")}.</div>`;
    if (data.warnings.length) html += `<div class="msg warn">À vérifier :<ul>${data.warnings.map((w) => `<li>${esc(w)}</li>`).join("")}</ul></div>`;
    $("#ocr-msg").innerHTML = html;
  }

  // ------------------------------------------------------------------ démarrage
  async function start() {
    cfg = await (await fetch("/admin/config")).json();
    $("#role-name").textContent = cfg.admin_role;
    // Derrière un tunnel HTTPS, l'interface doit être ouverte sur l'URL publique (même origine que Keycloak)
    const pub = new URL(cfg.public_url);
    if (pub.protocol === "https:" && location.origin !== pub.origin && !location.search) {
      location.replace(pub.origin + "/admin/"); return;
    }
    $("#login").onclick = login;
    $("#login").disabled = false;   // prêt (configuration chargée)
    $("#logout").onclick = logout;
    $("#new").onclick = () => openForm(null);
    $("#cancel").onclick = () => $("#form-panel").classList.add("hidden");
    $("#result-close").onclick = () => $("#result-panel").classList.add("hidden");
    $("#search").oninput = renderList;
    $("#rows").onclick = rowAction;
    $("#read-mrz").onclick = readMrz;
    $("#check").onclick = () => check(false);
    F().onsubmit = (e) => { e.preventDefault(); check(true); };
    $("#photo").onchange = onPhoto;
    bindDrop("recto"); bindDrop("verso");
    $("#ocr").onclick = runOcr;
    try {
      await handleCallback();
      tokens = tokens || JSON.parse(store.get("tokens") || "null");
      if (tokens && await accessToken()) showApp(); else showLogin();
    } catch (e) { showLogin(e.message); }
  }
  start();
})();
