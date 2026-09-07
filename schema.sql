-- ============================================================================
-- MINIMAL TEXT MESSENGER — DATABASE SCHEMA
-- Run this whole file once in the Supabase SQL Editor (SQL > New query).
-- Safe to re-run: guarded with IF NOT EXISTS / OR REPLACE where possible.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 0. EXTENSIONS
-- ----------------------------------------------------------------------------
create extension if not exists pgcrypto;   -- for gen_random_uuid()
-- pg_cron powers the optional 24h auto-delete job (section 6). It is
-- available on Supabase but must be enabled from the Dashboard:
-- Database > Extensions > pg_cron. If you don't enable it, everything
-- else in this file still works — you'll just skip section 6.

-- ----------------------------------------------------------------------------
-- 1. PROFILES TABLE
-- One row per registered user. id == auth.users.id (Supabase Auth).
-- permanent_user_id is the public, human-facing, unchangeable identifier
-- ("USR-7K4P92") that users search each other by.
-- public_key is the user's ECDH public key (JWK, as text) used for
-- client-side end-to-end encryption. It is not secret — it MUST be
-- readable by other users so they can encrypt messages to this user.
-- ----------------------------------------------------------------------------
create table if not exists public.profiles (
  id                 uuid primary key references auth.users(id) on delete cascade,
  permanent_user_id  text not null unique,
  name               text not null,
  icon_id            smallint not null check (icon_id between 0 and 7),
  public_key         text not null,
  created_at         timestamptz not null default now()
);

-- Enforce the USR-XXXXXX shape at the database level so nothing malformed
-- can ever be inserted, regardless of what the client sends.
alter table public.profiles
  drop constraint if exists profiles_permanent_user_id_format;
alter table public.profiles
  add constraint profiles_permanent_user_id_format
  check (permanent_user_id ~ '^USR-[A-Z0-9]{6}$');

alter table public.profiles
  drop constraint if exists profiles_name_length;
alter table public.profiles
  add constraint profiles_name_length
  check (char_length(trim(name)) between 1 and 40);

create index if not exists idx_profiles_permanent_user_id
  on public.profiles (permanent_user_id);

-- ----------------------------------------------------------------------------
-- 2. MESSAGES TABLE
-- message_content stores the E2EE payload as JSON text:
--   { "iv": "<base64>", "ciphertext": "<base64>" }
-- The server only ever sees ciphertext. See crypto.js for the client-side
-- encryption/decryption implementation and README.md section "Encryption
-- model & its real limits" for what this does and does NOT protect against.
-- ----------------------------------------------------------------------------
create table if not exists public.messages (
  id               uuid primary key default gen_random_uuid(),
  sender_id        uuid not null references public.profiles(id) on delete cascade,
  receiver_id      uuid not null references public.profiles(id) on delete cascade,
  message_content  text not null check (char_length(message_content) between 1 and 20000),
  created_at       timestamptz not null default now()
);

-- Composite indexes so a conversation (a pair of users, in either
-- direction) and "my chat list, most recent first" both stay fast as the
-- table grows.
create index if not exists idx_messages_sender_receiver_created
  on public.messages (sender_id, receiver_id, created_at desc);
create index if not exists idx_messages_receiver_sender_created
  on public.messages (receiver_id, sender_id, created_at desc);
create index if not exists idx_messages_created_at
  on public.messages (created_at);

-- ----------------------------------------------------------------------------
-- 3. ROW LEVEL SECURITY
-- ----------------------------------------------------------------------------
alter table public.profiles enable row level security;
alter table public.messages enable row level security;

-- --- profiles policies -------------------------------------------------

-- Deliberately NOT "using (true)". A plain "any authenticated user can
-- read any profile" policy would let a client bypass the app's UI and
-- call profiles.select('*') directly to dump every user's permanent ID
-- and name — turning "search by exact ID only" (spec section 4) into
-- "browse everyone." Instead, direct table reads are limited to:
--   - your own profile, and
--   - profiles of people you already have a conversation with
--     (needed to show their name/icon in the chat list and chat screen).
-- Exact-ID search itself is served by the find_user_by_permanent_id()
-- function below, which does a single-row exact-match lookup and cannot
-- be used to enumerate the user base.
drop policy if exists "profiles are readable by any authenticated user" on public.profiles;
drop policy if exists "profiles readable by self or conversation partner" on public.profiles;
create policy "profiles readable by self or conversation partner"
  on public.profiles for select
  to authenticated
  using (
    id = auth.uid()
    or exists (
      select 1 from public.messages m
      where (m.sender_id = auth.uid() and m.receiver_id = profiles.id)
         or (m.receiver_id = auth.uid() and m.sender_id = profiles.id)
    )
  );

-- A user may create only their own profile row, exactly once, and only
-- with an id matching their own auth uid.
drop policy if exists "users can insert their own profile" on public.profiles;
create policy "users can insert their own profile"
  on public.profiles for insert
  to authenticated
  with check (id = auth.uid());

-- name, permanent_user_id and icon_id must never change after
-- registration (section 3 of the spec). public_key is the one
-- exception: if a user opens the app on a new device/browser (or clears
-- site data), their old private key is gone (see crypto.js — private
-- keys never leave the device they were created on) and the app offers
-- to generate a fresh local keypair so they can keep messaging. That
-- requires updating public_key. The trigger below enforces, at the
-- database level, that this UPDATE path can change public_key and
-- NOTHING else — a client cannot smuggle a name/id/icon change in.
drop policy if exists "users can rotate their own public key" on public.profiles;
create policy "users can rotate their own public key"
  on public.profiles for update
  to authenticated
  using (id = auth.uid())
  with check (id = auth.uid());

create or replace function public.protect_immutable_profile_fields()
returns trigger
language plpgsql
as $$
begin
  if new.permanent_user_id is distinct from old.permanent_user_id
     or new.name is distinct from old.name
     or new.icon_id is distinct from old.icon_id
     or new.id is distinct from old.id then
    raise exception 'This field cannot be changed.';
  end if;
  return new;
end;
$$;

drop trigger if exists trg_protect_immutable_profile_fields on public.profiles;
create trigger trg_protect_immutable_profile_fields
  before update on public.profiles
  for each row execute function public.protect_immutable_profile_fields();

-- No policy grants DELETE directly on profiles either — account deletion
-- is handled by the delete-account Edge Function using the service role
-- key (see supabase/functions/delete-account), never by the client
-- deleting its own row.

-- --- messages policies --------------------------------------------------

-- A user may read a message only if they are the sender or the receiver.
drop policy if exists "participants can read their messages" on public.messages;
create policy "participants can read their messages"
  on public.messages for select
  to authenticated
  using (auth.uid() = sender_id or auth.uid() = receiver_id);

-- Helper used by the INSERT policy below. IMPORTANT: a policy's WITH
-- CHECK expression runs under the INSERTING user's own RLS, so a plain
-- "exists (select 1 from profiles where id = receiver_id)" would be
-- filtered by the profiles SELECT policy above — which (correctly)
-- hides a brand-new contact you have no conversation with yet. That
-- would block the very first message of every new conversation. This
-- security-definer function bypasses that and only ever answers a
-- yes/no existence question, so it can't be used to read any profile
-- data.
create or replace function public.profile_exists(uid uuid)
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (select 1 from public.profiles where id = uid);
$$;

grant execute on function public.profile_exists(uuid) to authenticated;

-- A user may insert a message only as themselves (cannot forge sender_id)
-- and only to a receiver that actually exists.
drop policy if exists "users can send messages as themselves" on public.messages;
create policy "users can send messages as themselves"
  on public.messages for insert
  to authenticated
  with check (
    auth.uid() = sender_id
    and public.profile_exists(receiver_id)
  );

-- A user may delete a message only if they are a participant in it.
-- "Delete Chat" deletes every message where the current user is sender
-- or receiver and the other party is the selected conversation partner —
-- see app.js deleteChat(). Because every message has exactly two
-- participants, this permanently removes the conversation for both
-- people, not just the user who tapped delete. There is no per-user
-- "hide for me only" state in this minimal design — see README.md.
drop policy if exists "participants can delete their messages" on public.messages;
create policy "participants can delete their messages"
  on public.messages for delete
  to authenticated
  using (auth.uid() = sender_id or auth.uid() = receiver_id);

-- No UPDATE policy on messages: messages are immutable once sent
-- (no message editing, per spec).

-- ----------------------------------------------------------------------------
-- 4. UNIQUE, SERVER-GENERATED PERMANENT USER IDs
-- The client never invents a permanent_user_id. It asks the database for
-- one via this function, which loops until it finds an id that is not
-- already taken, so collisions are handled server-side (see section 1 of
-- the spec: "duplicate account generation collision").
-- ----------------------------------------------------------------------------
create or replace function public.generate_permanent_user_id()
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  chars text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; -- no 0/O/1/I to avoid confusion
  candidate text;
  i int;
  tries int := 0;
begin
  loop
    candidate := 'USR-';
    for i in 1..6 loop
      candidate := candidate || substr(chars, floor(random() * length(chars) + 1)::int, 1);
    end loop;

    exit when not exists (
      select 1 from public.profiles where permanent_user_id = candidate
    );

    tries := tries + 1;
    if tries > 50 then
      raise exception 'Could not generate a unique user id, please try again';
    end if;
  end loop;

  return candidate;
end;
$$;

-- Any authenticated (mid-registration) user can call this — it only ever
-- returns a fresh id string, it does not read or write anyone's data.
grant execute on function public.generate_permanent_user_id() to authenticated;

-- ----------------------------------------------------------------------------
-- 5. LOOK UP AN AUTH EMAIL BY PERMANENT USER ID (for login)
-- Supabase Auth signs in with an email + password. Because this app has
-- no real email, each account is registered internally with a synthetic
-- address like "usr-7k4p92@msgr.local" (see supabase-client.js). This
-- function lets the login screen turn "USR-7K4P92" + password into that
-- internal email, without ever exposing the auth.users table to clients.
-- It is intentionally NOT security-sensitive: the synthetic email is
-- derived deterministically from public data, and the real gate is the
-- password check performed by Supabase Auth itself in the next step.
-- ----------------------------------------------------------------------------
create or replace function public.permanent_user_id_exists(pid text)
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (select 1 from public.profiles where permanent_user_id = pid);
$$;

grant execute on function public.permanent_user_id_exists(text) to anon, authenticated;

-- ----------------------------------------------------------------------------
-- 5b. EXACT-MATCH USER SEARCH (the ONLY way to discover another user)
-- Bypasses the restrictive profiles SELECT policy above on purpose, but
-- only ever returns the single row matching an exact permanent_user_id
-- the caller already typed in full — it cannot list, paginate, or
-- fuzzy-match, so it cannot be used to enumerate users the way a bare
-- "select * from profiles" could.
-- ----------------------------------------------------------------------------
create or replace function public.find_user_by_permanent_id(pid text)
returns table (
  id uuid,
  permanent_user_id text,
  name text,
  icon_id smallint,
  public_key text
)
language sql
security definer
set search_path = public
stable
as $$
  select p.id, p.permanent_user_id, p.name, p.icon_id, p.public_key
  from public.profiles p
  where p.permanent_user_id = pid;
$$;

grant execute on function public.find_user_by_permanent_id(text) to authenticated;

-- ----------------------------------------------------------------------------
-- 6. OPTIONAL: 24-HOUR SERVER-SIDE MESSAGE RETENTION
-- Deletes messages older than 24 hours. This is a server-side scheduled
-- job (pg_cron), NOT client JavaScript, per spec section 16. It is
-- disabled by default — run the "schedule" statement at the bottom only
-- if you want this behaviour.
-- ----------------------------------------------------------------------------
create or replace function public.delete_expired_messages()
returns void
language sql
security definer
set search_path = public
as $$
  delete from public.messages where created_at < now() - interval '24 hours';
$$;

-- To ENABLE the 24h auto-delete policy:
--   1. In the Supabase Dashboard, go to Database > Extensions and enable "pg_cron".
--   2. Then run this statement once (uncomment it first):
--
-- select cron.schedule(
--   'delete-expired-messages',   -- job name
--   '*/15 * * * *',              -- every 15 minutes
--   $$ select public.delete_expired_messages(); $$
-- );
--
-- To DISABLE it later: select cron.unschedule('delete-expired-messages');
--
-- Note: this deletes rows from the Supabase database only. It does not
-- and cannot reach copies a recipient may have kept elsewhere (e.g. a
-- screenshot). See README.md for the exact wording the app uses about this.

-- ----------------------------------------------------------------------------
-- 7. CHAT LIST QUERY
-- Returns one row per conversation the CALLER is part of: the other
-- participant's profile info, plus their most recent message together.
-- Runs server-side against the indexes from section 2, so it stays fast
-- as the messages table grows instead of pulling every message to the
-- client just to compute "last message per conversation" in JavaScript.
-- security definer + a hard "auth.uid()" filter means a caller can only
-- ever get their own chat list, never anyone else's.
-- ----------------------------------------------------------------------------
create or replace function public.get_chat_list()
returns table (
  counterpart_id uuid,
  counterpart_permanent_user_id text,
  counterpart_name text,
  counterpart_icon_id smallint,
  counterpart_public_key text,
  last_message_content text,
  last_message_sender_id uuid,
  last_message_created_at timestamptz
)
language sql
security definer
set search_path = public
stable
as $$
  with my_messages as (
    select
      case when sender_id = auth.uid() then receiver_id else sender_id end as counterpart_id,
      message_content,
      sender_id,
      created_at
    from public.messages
    where sender_id = auth.uid() or receiver_id = auth.uid()
  ),
  ranked as (
    select
      m.*,
      row_number() over (partition by counterpart_id order by created_at desc) as rn
    from my_messages m
  )
  select
    r.counterpart_id,
    p.permanent_user_id,
    p.name,
    p.icon_id,
    p.public_key,
    r.message_content,
    r.sender_id,
    r.created_at
  from ranked r
  join public.profiles p on p.id = r.counterpart_id
  where r.rn = 1
  order by r.created_at desc;
$$;

grant execute on function public.get_chat_list() to authenticated;

-- ============================================================================
-- End of schema.sql
-- ============================================================================
