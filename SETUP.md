# hush — setup & deployment guide

A mobile-first web app: HTML + CSS + vanilla JavaScript on the frontend,
Supabase (Postgres + Auth + Realtime) as the real backend. No frameworks,
no build step, no media, no social features — just text messages between
two people, identified only by a permanent User ID.

> Looking for a project overview instead? See [`README.md`](./README.md).

```
/
├── index.html
├── style.css
├── app.js
├── crypto.js              — client-side E2EE (Web Crypto API)
├── supabase-client.js     — Supabase init + auth adapter
├── schema.sql             — full database schema, RLS, indexes, functions
├── supabase/
│   └── functions/
│       └── delete-account/
│           └── index.ts   — Edge Function (needs service role key)
└── README.md
```

`supabase-client.js` and the `delete-account` Edge Function are the two
files beyond the minimal five requested in the spec. Both exist for a
security reason explained inline where they're used (short version:
Supabase Auth needs an email-shaped identifier internally, and deleting
an `auth.users` row requires the service role key, which must never sit
in frontend code).

---

## 1. Create the Supabase project

1. Go to [supabase.com](https://supabase.com) and create a new project.
2. Wait for provisioning to finish, then open **SQL Editor**.
3. Paste the entire contents of `schema.sql` and run it. This creates:
   - `profiles` and `messages` tables, with foreign keys, uniqueness
     constraints, and indexes
   - Row Level Security policies on both tables
   - Helper functions (`generate_permanent_user_id`,
     `find_user_by_permanent_id`, `get_chat_list`, etc.)
4. (Optional) Enable the 24-hour auto-delete job — see section 6 below.
5. Go to **Database → Replication** and turn on replication for the
   `messages` table. This is what lets Supabase Realtime push new
   messages to the recipient's open chat instantly instead of the app
   having to poll — without it, messages still send and save correctly,
   they just won't appear on the other person's screen until they
   reopen the chat.

## 2. Configure Supabase Auth

This app logs in with a **User ID + password**, not an email — but under
the hood it uses Supabase's standard, secure email/password auth with a
synthetic, never-shown email like `usr-7k4p92@msgr.local` (see the
comment block at the top of `supabase-client.js` for why).

In **Authentication → Providers → Email**:

- **Turn OFF "Confirm email."** There is no real mailbox behind these
  addresses, so a confirmation email can never be delivered — leaving
  this on would lock every new account out immediately after signup.
- Leave "Enable Email provider" on. You don't need any other provider.

In **Authentication → Settings**, the defaults (session length, refresh
tokens, rate limits) are fine for this app — Supabase's built-in rate
limiting on signups/logins is one of the reasons this app rides on
Supabase Auth instead of a hand-rolled password check.

## 3. Get your API keys and wire up the frontend

In **Project Settings → API**, copy:

- **Project URL**
- **anon / public key**

Open `supabase-client.js` and replace:

```js
const SUPABASE_URL = "https://YOUR-PROJECT-REF.supabase.co";
const SUPABASE_ANON_KEY = "YOUR-ANON-PUBLIC-KEY";
```

The anon key is safe to ship in frontend code — every request it makes
is still constrained by the RLS policies in `schema.sql`. **Never** put
the **service_role** key anywhere in `supabase-client.js`, `app.js`, or
any other frontend file.

## 4. Deploy the `delete-account` Edge Function

This is the one operation the frontend cannot safely do itself: deleting
a Supabase Auth user requires the service role key.

```bash
npm install -g supabase        # if you don't already have the CLI
supabase login
supabase link --project-ref YOUR-PROJECT-REF
supabase functions deploy delete-account
```

Supabase automatically injects `SUPABASE_URL` and
`SUPABASE_SERVICE_ROLE_KEY` into the function's runtime — you do not set
those yourself, and they never touch the browser.

## 5. Run it locally

No build step, no `npm install` needed for the app itself. Any static
file server works, e.g.:

```bash
npx serve .
# or
python3 -m http.server 8080
```

Then open the printed local URL on your phone (same Wi-Fi) or in a
desktop browser's mobile emulation mode.

## 6. (Optional) Turn on 24-hour message auto-deletion

By default, messages are kept until a user deletes the conversation or
their account. To also auto-delete anything older than 24 hours:

1. In the Supabase Dashboard, go to **Database → Extensions** and
   enable **pg_cron**.
2. In the SQL Editor, run the commented-out block at the bottom of
   `schema.sql`'s section 6 (uncomment the `select cron.schedule(...)`
   statement and run it).

This runs entirely inside Postgres on a schedule — never in the
browser, per the spec. You can disable it later with
`select cron.unschedule('delete-expired-messages');`.

Important: this deletes rows from the Supabase database only. It says
nothing about, and cannot reach, any copy someone made another way
(e.g. a screenshot). The app never claims otherwise.

---

## Encryption model & its real limits

Messages are encrypted **on the sender's device** before they're sent,
and decrypted **on the recipient's device** after they arrive. Supabase
only ever stores ciphertext in `messages.message_content`.

- **Key exchange:** ECDH, curve P-256 (Web Crypto API)
- **Message cipher:** AES-GCM, 256-bit key, random IV per message
- No custom/home-grown cryptography — both primitives are standard,
  built into every modern browser.

Each account has one keypair, generated on the device at registration.
The **public** key is stored in `profiles.public_key` so others can
encrypt to that account. The **private** key is stored only in that
browser's IndexedDB and is **never** uploaded anywhere.

**What this does NOT give you** — please read this honestly rather than
take "end-to-end encrypted" as a blanket guarantee:

- **No multi-device sync.** Log in on a new device, or clear site data,
  and the old private key is gone. That device gets a fresh keypair
  (the app walks you through this — see "New device detected"), but it
  can never decrypt messages sent to the old key. This is a real,
  unresolved limitation of this minimal stack, not a hidden bug —
  building safe multi-device key sync (what Signal does with device
  linking and safety numbers) is a substantial protocol in its own
  right and is out of scope here.
- **No protection against a compromised endpoint.** Malware on your
  phone, or someone with your unlocked device, can read messages the
  same way you can.
- **No protection against the other participant.** They can always
  screenshot, copy, or forward what they've decrypted — encryption
  protects data in transit and at rest on the server, not what a
  recipient chooses to do with it afterward.
- **Metadata is not encrypted.** Supabase's database always knows *who*
  messaged *whom* and *when* (`sender_id`, `receiver_id`,
  `created_at`) — only the message text itself is encrypted. This app
  never describes itself as "untraceable" or "impossible to track,"
  because it isn't.
- **No password recovery.** There is no email or phone number on file,
  by design, so there is no "forgot password" flow. Losing your
  password means permanently losing access to that account.

---

## Other deliberate limitations (by design, not oversights)

- **Deleting a chat deletes it for both people.** Every message row has
  exactly two participants and no per-user "hide for me" state (adding
  one would be exactly the kind of extra feature the spec asks to leave
  out). "Delete Chat" removes every message between you and that person
  for both accounts, permanently.
- **No message editing or retraction**, per spec — once sent, a message
  is immutable until it's deleted along with the rest of the
  conversation.
- **Search only works on an exact, full Permanent User ID.** There is
  no partial match, name search, or "browse users" — this is enforced
  both in the UI and at the database level (see `schema.sql` section
  3's comments on why `profiles` isn't broadly readable).

---

## Converting the site into an Android APK

This app is plain static HTML/CSS/JS with no server-side rendering, so
any WebView-wrapper tool works. Two straightforward options:

### Option A — Capacitor (open source, most control)

```bash
npm install -g @capacitor/cli
mkdir hush-android && cd hush-android
npm init -y
npm install @capacitor/core @capacitor/android
npx cap init hush com.yourname.hush
```

1. Copy `index.html`, `style.css`, `app.js`, `crypto.js`, and
   `supabase-client.js` into a `www/` folder in this new project.
2. In `capacitor.config.json`, set `"webDir": "www"`.
3. Add the Android platform and open it in Android Studio:
   ```bash
   npx cap add android
   npx cap sync
   npx cap open android
   ```
4. Build → Generate Signed Bundle/APK in Android Studio.

Capacitor apps run in a real Android WebView, so everything used here
(Web Crypto API, IndexedDB, fetch, Supabase Realtime over WebSockets)
works unchanged.

### Option B — A hosted WebView-wrapper service

If you'd rather not touch Android Studio, deploy the site to any static
host (Vercel, Netlify, GitHub Pages, or your own server over **HTTPS —
required** for the Web Crypto API and Supabase Realtime to work) and
point a WebView-wrapper service (e.g. Median, GoNative) at the public
URL. These produce a signed APK/AAB without local Android tooling, at
the cost of less control than Capacitor.

Either way: **serve over HTTPS**. Browsers restrict `crypto.subtle` and
`indexedDB` on insecure origins, and Supabase's client requires a secure
context in production.

---

## Security checklist (self-audit before calling this done)

- [x] Service role key never appears in any frontend file — only inside
      the `delete-account` Edge Function's server-side runtime.
- [x] RLS enabled on both `profiles` and `messages`, with `FOR SELECT /
      INSERT / UPDATE / DELETE` policies scoped to `auth.uid()`.
- [x] `profiles` is **not** broadly readable — only your own row, a
      conversation partner's row, or an exact-ID match via
      `find_user_by_permanent_id()`. Prevents user-directory
      enumeration via a raw `select * from profiles`.
- [x] `permanent_user_id`, `name`, and `icon_id` are immutable after
      creation, enforced by a database trigger — not just by hiding the
      UI for it.
- [x] Messages can only be inserted with `sender_id = auth.uid()` — a
      user cannot forge messages as someone else.
- [x] Message and profile IDs are checked with a `CHECK` constraint
      (`USR-` + 6 chars) so malformed IDs can't reach the database.
- [x] No plaintext message content stored server-side — only the
      AES-GCM ciphertext and IV.
- [x] No image/file upload code paths exist anywhere in the app.
- [x] Every user-facing error (`login-error`, `search-not-found`,
      toast messages) is a plain, generic string — no raw Postgres or
      Supabase error text is ever shown to the user.
