<div align="center">

# hush.

**A private, minimal, text-only messenger.**

*Text only. Nothing else.*

![Status](https://img.shields.io/badge/status-active-6FA98A)
![Frontend](https://img.shields.io/badge/frontend-HTML%20%7C%20CSS%20%7C%20Vanilla%20JS-7C93C9)
![Backend](https://img.shields.io/badge/backend-Supabase-1E2830)
![Encryption](https://img.shields.io/badge/encryption-AES--GCM%20%2B%20ECDH-C98E6F)

</div>

---

## What is this?

**hush** is a stripped-down, mobile-first chat app built around one idea: a
messenger doesn't need feeds, stories, read receipts, or media sharing to be
useful — it just needs to get a text message from one person to another,
privately, and get out of the way.

No email. No phone number. No profile pictures. No social graph. Just a
name, a password, and a permanent ID that's the only way anyone can find you.

There is no server framework and no build step — the entire frontend is
plain HTML, CSS, and vanilla JavaScript, backed by [Supabase](https://supabase.com)
for the database, authentication, and realtime delivery.

---

## Features

| | |
|---|---|
| 🪪 **Identity-light accounts** | Sign up with just a name and password — no email or phone required |
| 🔍 **Exact-ID search only** | The only way to find someone is their permanent `USR-XXXXXX` ID — no directory, no browsing |
| 🔒 **Client-side encryption** | Messages are encrypted on your device before they ever reach the server (ECDH + AES-GCM) |
| ⚡ **Realtime delivery** | New messages appear instantly via Supabase Realtime — no polling |
| 🧹 **Minimal by design** | No stories, reactions, read receipts, typing indicators, groups, or media — on purpose |
| 🗑️ **Clean deletion** | Delete a conversation or your whole account, with no hidden leftovers |
| 📱 **Mobile-first** | Built for a phone screen first, works fine on desktop too |

---

## Screenshots

<div align="center">
<i>Add screenshots of the login, chat list, and chat screen here once you have them —<br/>drop the image files into a <code>/screenshots</code> folder and reference them below.</i>

<!--
<img src="screenshots/login.png" width="220" />
<img src="screenshots/chat-list.png" width="220" />
<img src="screenshots/chat.png" width="220" />
-->
</div>

---

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3, vanilla JavaScript — no frameworks, no build tooling |
| Backend | [Supabase](https://supabase.com) — Postgres, Auth, Realtime, Edge Functions |
| Encryption | Web Crypto API — ECDH (P-256) key exchange, AES-GCM message cipher |
| Security | Postgres Row Level Security on every table, no service-role key in the frontend |
| Deployment | Any static host (this project runs on Vercel) |
| Mobile | Wrapped into an Android APK via an HTML-to-APK / WebView tool |

---

## How it works, briefly

```
┌─────────────┐        encrypted message         ┌─────────────┐
│   Device A  │ ───────────────────────────────▶ │   Device B  │
│ (has priv.  │                                    │ (has priv.  │
│  key A)     │ ◀─────────────────────────────── │  key B)     │
└─────────────┘        encrypted message         └─────────────┘
       │                                                  │
       │              public keys only                    │
       ▼                                                  ▼
              ┌────────────────────────────┐
              │           Supabase          │
              │  Postgres · Auth · Realtime │
              │   (only ever sees            │
              │    ciphertext)               │
              └────────────────────────────┘
```

Each account generates an encryption keypair on-device at signup. The
**public** key is stored in the database so others can encrypt to you; the
**private** key never leaves the device it was created on. Supabase's
Row Level Security policies make sure no user can read, modify, or delete
another user's data — even with direct API access, not just through the UI.

For the full breakdown of the encryption model and its honest limitations
(no multi-device sync, no password recovery, etc.), see
[`SETUP.md`](./SETUP.md#encryption-model--its-real-limits).

---

## Getting started

This README covers the *what*. For the full *how* — creating the Supabase
project, running the schema, configuring Auth, deploying the Edge Function,
hosting the site, and wrapping it into an Android APK — see:

### 📄 [SETUP.md](./SETUP.md)

---

## Project structure

```
hush/
├── index.html               UI — all screens (login, chat, search, account)
├── style.css                Mobile-first styling
├── app.js                   App logic, screens, Supabase queries
├── crypto.js                Client-side end-to-end encryption
├── supabase-client.js       Supabase init + auth adapter
├── schema.sql                Database schema, RLS policies, indexes
├── supabase/
│   └── functions/
│       └── delete-account/  Edge Function for secure account deletion
├── SETUP.md                 Full setup & deployment guide
└── README.md                 You are here
```

---

## Security at a glance

- Row Level Security enabled on every table — a user can only ever read or
  write their own data, enforced by Postgres, not just the UI.
- The `service_role` key never appears in any frontend file — it's used
  only inside the Edge Function's server-side runtime.
- User search only works on an exact permanent ID — there is no way to
  list or enumerate the user base.
- Names, IDs, and icons are immutable after signup, enforced at the
  database level with a trigger.
- No image, file, or media upload code paths exist anywhere in the app.

## Design principles

This project follows one rule above all others: **if it wasn't explicitly
asked for, it doesn't go in.** No feature creep, no "since we're at it"
additions. It's meant to stay a train with every unnecessary carriage
removed — not a messaging app that quietly grows into a social network.

## License

Add your preferred license here (MIT, Apache 2.0, or otherwise) before
publishing this repository publicly.

---

<div align="center">
<i>Private • Minimal • Fast • Clean</i>
</div>
