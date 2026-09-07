/**
 * app.js — application logic, screens, and Supabase data access.
 * Vanilla JS only. No frameworks, no build step.
 */
(function () {
  "use strict";

  const sb = window.MessengerAuth.supabaseClient;
  const Crypto = window.MessengerCrypto;

  // Small, fixed, built-in icon set. Only the index (0-7) is ever stored
  // in the database (profiles.icon_id) — no images, no uploads.
  const ICONS = [
    { glyph: "●", color: "#6FA98A" },
    { glyph: "◆", color: "#7C93C9" },
    { glyph: "▲", color: "#C98E6F" },
    { glyph: "★", color: "#B389C9" },
    { glyph: "■", color: "#C97C93" },
    { glyph: "⬢", color: "#6FB3C9" },
    { glyph: "✦", color: "#9BC96F" },
    { glyph: "◈", color: "#C9AC6F" },
  ];

  const USER_ID_PATTERN = /^USR-[A-Z0-9]{6}$/;

  /** @type {{id:string, permanentUserId:string, name:string, iconId:number, publicKey:string}|null} */
  let me = null;
  let currentChatPartner = null; // profile-shaped object of the open chat's other participant
  let realtimeChannel = null;
  let chatListCache = []; // last fetched chat list, for quick re-render

  // -------------------------------------------------------------------
  // Small DOM helpers
  // -------------------------------------------------------------------

  const $ = (sel) => document.querySelector(sel);
  const $all = (sel) => Array.from(document.querySelectorAll(sel));

  function showScreen(id) {
    $all(".screen").forEach((el) => el.classList.remove("screen--active"));
    $(`#${id}`).classList.add("screen--active");
  }

  function setError(elId, message) {
    const el = $(`#${elId}`);
    el.textContent = message || "";
    el.classList.toggle("field-error--visible", Boolean(message));
  }

  function iconEl(iconId, size) {
    const icon = ICONS[iconId] ?? ICONS[0];
    const span = document.createElement("span");
    span.className = "avatar";
    if (size) span.style.setProperty("--avatar-size", size);
    span.style.background = icon.color;
    span.textContent = icon.glyph;
    return span;
  }

  function formatTime(iso) {
    const d = new Date(iso);
    const now = new Date();
    const sameDay = d.toDateString() === now.toDateString();
    if (sameDay) {
      return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }
    return d.toLocaleDateString([], { month: "short", day: "numeric" });
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // -------------------------------------------------------------------
  // Toast / inline banner for transient errors (network failures etc.)
  // -------------------------------------------------------------------

  let toastTimer = null;
  function showToast(message) {
    const toast = $("#toast");
    toast.textContent = message;
    toast.classList.add("toast--visible");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("toast--visible"), 3200);
  }

  // -------------------------------------------------------------------
  // Bootstrapping / session restore
  // -------------------------------------------------------------------

  async function init() {
    wireStaticEvents();

    const session = await window.MessengerAuth.getCurrentSession();
    if (!session) {
      showScreen("screen-login");
      return;
    }

    try {
      await loadMyProfile(session.user.id);
    } catch (err) {
      console.error(err);
      showToast("Session expired. Please log in again.");
      await window.MessengerAuth.logout();
      showScreen("screen-login");
      return;
    }

    const hasKey = await Crypto.hasDeviceKey();
    if (!hasKey) {
      showScreen("screen-new-device");
      return;
    }

    enterApp();
  }

  async function loadMyProfile(userId) {
    const { data, error } = await sb
      .from("profiles")
      .select("id, permanent_user_id, name, icon_id, public_key")
      .eq("id", userId)
      .single();

    if (error || !data) throw new Error("Could not load profile.");

    me = {
      id: data.id,
      permanentUserId: data.permanent_user_id,
      name: data.name,
      iconId: data.icon_id,
      publicKey: data.public_key,
    };
  }

  function enterApp() {
    renderAccountScreen();
    showScreen("screen-main");
    loadChatList();
    subscribeRealtime();
  }

  // -------------------------------------------------------------------
  // Registration
  // -------------------------------------------------------------------

  async function handleRegisterSubmit(e) {
    e.preventDefault();
    setError("register-error", "");

    const name = $("#register-name").value;
    const password = $("#register-password").value;
    const button = $("#register-submit");

    button.disabled = true;
    button.textContent = "Creating account…";

    try {
      const result = await window.MessengerAuth.registerAccount(name, password);
      await loadMyProfile((await window.MessengerAuth.getCurrentSession()).user.id);
      showWelcomeId(result.permanentUserId);
    } catch (err) {
      setError("register-error", err.message || "Could not create account.");
    } finally {
      button.disabled = false;
      button.textContent = "Create account";
    }
  }

  function showWelcomeId(permanentUserId) {
    $("#welcome-id-value").textContent = permanentUserId;
    showScreen("screen-welcome-id");
  }

  function handleWelcomeContinue() {
    enterApp();
  }

  // -------------------------------------------------------------------
  // Login
  // -------------------------------------------------------------------

  async function handleLoginSubmit(e) {
    e.preventDefault();
    setError("login-error", "");

    const id = $("#login-id").value.trim().toUpperCase();
    const password = $("#login-password").value;
    const button = $("#login-submit");

    button.disabled = true;
    button.textContent = "Logging in…";

    try {
      const data = await window.MessengerAuth.loginWithUserId(id, password);
      await loadMyProfile(data.user.id);

      const hasKey = await Crypto.hasDeviceKey();
      if (!hasKey) {
        showScreen("screen-new-device");
      } else {
        enterApp();
      }
    } catch (err) {
      setError("login-error", err.message || "Login failed.");
    } finally {
      button.disabled = false;
      button.textContent = "Log in";
    }
  }

  // -------------------------------------------------------------------
  // New-device / lost-key flow (see crypto.js "HONEST LIMITATION")
  // -------------------------------------------------------------------

  async function handleGenerateNewKey() {
    const button = $("#new-device-continue");
    button.disabled = true;
    button.textContent = "Setting up…";
    try {
      const publicKeyJson = await Crypto.generateAndStoreKeyPair();
      const { error } = await sb
        .from("profiles")
        .update({ public_key: publicKeyJson })
        .eq("id", me.id);
      if (error) throw error;
      enterApp();
    } catch (err) {
      console.error(err);
      showToast("Could not set up encryption on this device. Please try again.");
    } finally {
      button.disabled = false;
      button.textContent = "Continue";
    }
  }

  // -------------------------------------------------------------------
  // Chat list (main screen)
  // -------------------------------------------------------------------

  async function loadChatList() {
    const listEl = $("#chat-list");
    const emptyEl = $("#chat-list-empty");

    const { data, error } = await sb.rpc("get_chat_list");
    if (error) {
      showToast("Could not load your chats.");
      return;
    }

    chatListCache = data || [];

    if (chatListCache.length === 0) {
      listEl.innerHTML = "";
      emptyEl.hidden = false;
      return;
    }
    emptyEl.hidden = true;

    const rows = await Promise.all(
      chatListCache.map(async (row) => {
        let preview = "…";
        try {
          preview = await Crypto.decryptMessage(row.last_message_content, row.counterpart_public_key);
        } catch {
          preview = "[Unable to decrypt on this device]";
        }
        return { row, preview };
      })
    );

    listEl.innerHTML = "";
    for (const { row, preview } of rows) {
      const li = document.createElement("li");
      li.className = "chat-row";
      li.tabIndex = 0;
      li.dataset.counterpartId = row.counterpart_id;

      const avatar = iconEl(row.counterpart_icon_id);
      const info = document.createElement("div");
      info.className = "chat-row__info";
      info.innerHTML = `
        <div class="chat-row__top">
          <span class="chat-row__name">${escapeHtml(row.counterpart_name)}</span>
          <span class="chat-row__time">${formatTime(row.last_message_created_at)}</span>
        </div>
        <div class="chat-row__bottom">
          <span class="chat-row__id">${escapeHtml(row.counterpart_permanent_user_id)}</span>
          <span class="chat-row__preview">${escapeHtml(preview)}</span>
        </div>
      `;

      li.appendChild(avatar);
      li.appendChild(info);
      li.addEventListener("click", () =>
        openChat({
          id: row.counterpart_id,
          permanent_user_id: row.counterpart_permanent_user_id,
          name: row.counterpart_name,
          icon_id: row.counterpart_icon_id,
          public_key: row.counterpart_public_key,
        })
      );
      listEl.appendChild(li);
    }
  }

  // -------------------------------------------------------------------
  // Search
  // -------------------------------------------------------------------

  function openSearchScreen() {
    $("#search-input").value = "";
    $("#search-result").innerHTML = "";
    $("#search-not-found").hidden = true;
    showScreen("screen-search");
    $("#search-input").focus();
  }

  async function handleSearchSubmit(e) {
    e.preventDefault();
    const raw = $("#search-input").value.trim().toUpperCase();
    const resultEl = $("#search-result");
    const notFoundEl = $("#search-not-found");
    resultEl.innerHTML = "";
    notFoundEl.hidden = true;

    if (!USER_ID_PATTERN.test(raw)) {
      notFoundEl.textContent = "Enter a valid User ID, e.g. USR-7K4P92.";
      notFoundEl.hidden = false;
      return;
    }

    if (raw === me.permanentUserId) {
      notFoundEl.textContent = "That's your own User ID.";
      notFoundEl.hidden = false;
      return;
    }

    const { data: rows, error } = await sb.rpc("find_user_by_permanent_id", { pid: raw });

    if (error) {
      showToast("Network error. Please try again.");
      return;
    }

    const data = rows && rows.length > 0 ? rows[0] : null;

    if (!data) {
      notFoundEl.textContent = "User not found.";
      notFoundEl.hidden = false;
      return;
    }

    const row = document.createElement("div");
    row.className = "chat-row chat-row--search";
    const avatar = iconEl(data.icon_id);
    const info = document.createElement("div");
    info.className = "chat-row__info";
    info.innerHTML = `
      <div class="chat-row__top"><span class="chat-row__name">${escapeHtml(data.name)}</span></div>
      <div class="chat-row__bottom"><span class="chat-row__id">${escapeHtml(data.permanent_user_id)}</span></div>
    `;
    const sendBtn = document.createElement("button");
    sendBtn.className = "btn btn--primary btn--compact";
    sendBtn.textContent = "Send Message";
    sendBtn.addEventListener("click", () => openChat(data));

    row.appendChild(avatar);
    row.appendChild(info);
    row.appendChild(sendBtn);
    resultEl.appendChild(row);
  }

  // -------------------------------------------------------------------
  // Chat screen
  // -------------------------------------------------------------------

  async function openChat(counterpart) {
    currentChatPartner = counterpart;
    $("#chat-header-name").textContent = counterpart.name;
    $("#chat-header-id").textContent = counterpart.permanent_user_id;
    $("#chat-header-avatar").innerHTML = "";
    $("#chat-header-avatar").appendChild(iconEl(counterpart.icon_id));
    $("#chat-messages").innerHTML = "";
    $("#chat-input").value = "";
    showScreen("screen-chat");

    const { data, error } = await sb
      .from("messages")
      .select("id, sender_id, receiver_id, message_content, created_at")
      .or(
        `and(sender_id.eq.${me.id},receiver_id.eq.${counterpart.id}),and(sender_id.eq.${counterpart.id},receiver_id.eq.${me.id})`
      )
      .order("created_at", { ascending: true });

    if (error) {
      showToast("Could not load messages.");
      return;
    }

    for (const msg of data) {
      await renderMessage(msg);
    }
    scrollChatToBottom();
    $("#chat-input").focus();
  }

  async function renderMessage(msg) {
    const mine = msg.sender_id === me.id;
    // ECDH's shared secret is symmetric — decrypting any message in this
    // conversation always uses (my private key, the other participant's
    // public key), regardless of who actually sent it.
    let text;
    try {
      text = await Crypto.decryptMessage(msg.message_content, currentChatPartner.public_key);
    } catch {
      text = "[Unable to decrypt this message on this device]";
    }

    const bubble = document.createElement("div");
    bubble.className = `bubble ${mine ? "bubble--mine" : "bubble--theirs"}`;
    bubble.dataset.messageId = msg.id;
    bubble.innerHTML = `
      <div class="bubble__text"></div>
      <div class="bubble__time">${formatTime(msg.created_at)}</div>
    `;
    bubble.querySelector(".bubble__text").textContent = text;
    $("#chat-messages").appendChild(bubble);
  }

  function scrollChatToBottom() {
    const container = $("#chat-messages");
    container.scrollTop = container.scrollHeight;
  }

  async function handleSendMessage(e) {
    e.preventDefault();
    const input = $("#chat-input");
    const text = input.value.trim();
    if (!text) return;
    if (!currentChatPartner) return;

    const sendBtn = $("#chat-send");
    sendBtn.disabled = true;

    try {
      const encrypted = await Crypto.encryptMessage(text, currentChatPartner.public_key);
      const { data, error } = await sb
        .from("messages")
        .insert({
          sender_id: me.id,
          receiver_id: currentChatPartner.id,
          message_content: encrypted,
        })
        .select()
        .single();

      if (error) throw error;

      input.value = "";
      await renderMessage(data);
      scrollChatToBottom();
      loadChatList();
    } catch (err) {
      console.error(err);
      showToast("Message could not be sent. Please try again.");
    } finally {
      sendBtn.disabled = false;
      input.focus();
    }
  }

  // -------------------------------------------------------------------
  // Delete chat
  // -------------------------------------------------------------------

  function openDeleteChatConfirm() {
    $("#confirm-modal-title").textContent = "Delete this conversation?";
    $("#confirm-modal-body").textContent =
      "This permanently deletes the messages for both people in this conversation. This can't be undone.";
    showModal(async () => {
      await deleteChat();
    });
  }

  async function deleteChat() {
    if (!currentChatPartner) return;
    const { error } = await sb
      .from("messages")
      .delete()
      .or(
        `and(sender_id.eq.${me.id},receiver_id.eq.${currentChatPartner.id}),and(sender_id.eq.${currentChatPartner.id},receiver_id.eq.${me.id})`
      );

    if (error) {
      showToast("Could not delete this conversation. Please try again.");
      return;
    }

    currentChatPartner = null;
    showScreen("screen-main");
    loadChatList();
  }

  // -------------------------------------------------------------------
  // Account screen / logout / delete account
  // -------------------------------------------------------------------

  function renderAccountScreen() {
    $("#account-avatar").innerHTML = "";
    $("#account-avatar").appendChild(iconEl(me.iconId));
    $("#account-name").textContent = me.name;
    $("#account-id").textContent = me.permanentUserId;
  }

  async function handleLogout() {
    if (realtimeChannel) sb.removeChannel(realtimeChannel);
    await window.MessengerAuth.logout();
    me = null;
    currentChatPartner = null;
    showScreen("screen-login");
  }

  function openDeleteAccountConfirm() {
    $("#confirm-modal-title").textContent = "Delete your account?";
    $("#confirm-modal-body").textContent =
      "This permanently deletes your account and every conversation you're part of. This can't be undone.";
    showModal(async () => {
      await handleDeleteAccount();
    });
  }

  async function handleDeleteAccount() {
    try {
      await window.MessengerAuth.deleteAccount();
      if (realtimeChannel) sb.removeChannel(realtimeChannel);
      me = null;
      currentChatPartner = null;
      showScreen("screen-login");
    } catch (err) {
      showToast(err.message || "Account deletion failed.");
    }
  }

  // -------------------------------------------------------------------
  // Confirmation modal (shared by delete chat / delete account)
  // -------------------------------------------------------------------

  let pendingConfirmAction = null;

  function showModal(onConfirm) {
    pendingConfirmAction = onConfirm;
    $("#confirm-modal").hidden = false;
  }

  function hideModal() {
    $("#confirm-modal").hidden = true;
    pendingConfirmAction = null;
  }

  async function handleModalConfirm() {
    const action = pendingConfirmAction;
    hideModal();
    if (action) await action();
  }

  // -------------------------------------------------------------------
  // Realtime — new incoming messages
  // -------------------------------------------------------------------

  function subscribeRealtime() {
    if (realtimeChannel) sb.removeChannel(realtimeChannel);

    realtimeChannel = sb
      .channel(`messages-for-${me.id}`)
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "messages", filter: `receiver_id=eq.${me.id}` },
        async (payload) => {
          const msg = payload.new;
          if (currentChatPartner && msg.sender_id === currentChatPartner.id) {
            await renderMessage(msg);
            scrollChatToBottom();
          }
          loadChatList();
        }
      )
      .subscribe();
  }

  // -------------------------------------------------------------------
  // Wire up static DOM events (called once on init)
  // -------------------------------------------------------------------

  function wireStaticEvents() {
    $("#form-login").addEventListener("submit", handleLoginSubmit);
    $("#form-register").addEventListener("submit", handleRegisterSubmit);
    $("#form-search").addEventListener("submit", handleSearchSubmit);
    $("#form-chat").addEventListener("submit", handleSendMessage);

    $("#link-go-register").addEventListener("click", () => showScreen("screen-register"));
    $("#link-go-login").addEventListener("click", () => showScreen("screen-login"));
    $("#welcome-id-continue").addEventListener("click", handleWelcomeContinue);
    $("#new-device-continue").addEventListener("click", handleGenerateNewKey);

    $("#btn-open-search").addEventListener("click", openSearchScreen);
    $("#btn-back-from-search").addEventListener("click", () => showScreen("screen-main"));
    $("#btn-back-from-chat").addEventListener("click", () => {
      currentChatPartner = null;
      showScreen("screen-main");
      loadChatList();
    });
    $("#btn-open-account").addEventListener("click", () => showScreen("screen-account"));
    $("#btn-back-from-account").addEventListener("click", () => showScreen("screen-main"));

    $("#chat-menu-btn").addEventListener("click", (e) => {
      e.stopPropagation();
      $("#chat-menu").classList.toggle("chat-menu--open");
    });
    $("#chat-menu-delete").addEventListener("click", () => {
      $("#chat-menu").classList.remove("chat-menu--open");
      openDeleteChatConfirm();
    });
    document.addEventListener("click", (e) => {
      const menu = $("#chat-menu");
      if (menu.classList.contains("chat-menu--open") && !menu.contains(e.target)) {
        menu.classList.remove("chat-menu--open");
      }
    });

    $("#btn-logout").addEventListener("click", handleLogout);
    $("#btn-delete-account").addEventListener("click", openDeleteAccountConfirm);

    $("#confirm-modal-cancel").addEventListener("click", hideModal);
    $("#confirm-modal-confirm").addEventListener("click", handleModalConfirm);
  }

  document.addEventListener("DOMContentLoaded", init);
})();
