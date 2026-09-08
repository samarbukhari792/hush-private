/**
 * supabase-client.js
 * ------------------------------------------------------------------
 * Initializes the Supabase client and wraps the parts of Supabase Auth
 * that need a small adapter because this app logs in with a Permanent
 * User ID + password instead of an email.
 *
 * WHY A SYNTHETIC EMAIL:
 * Supabase Auth's built-in, battle-tested password flow (hashing,
 * rate limiting, session/JWT issuance and refresh) is keyed on an
 * email address. Reimplementing password auth from scratch would mean
 * hand-rolling password hashing and session management — exactly the
 * kind of thing spec section 14 says not to trust to frontend code.
 * Instead, each account is registered with Supabase Auth using a
 * synthetic, non-routable address derived deterministically from the
 * permanent User ID, e.g. "usr-7k4p92@msgr.local". This address is
 * never shown in the UI and is not collected from the user — the user
 * only ever sees/enters their Permanent User ID and password.
 *
 * >>> REPLACE THESE TWO VALUES with your own project's values <<<
 * Find them in: Supabase Dashboard > Project Settings > API.
 * The anon/public key is safe to ship in frontend code — it only works
 * within the Row Level Security policies defined in schema.sql.
 * NEVER put the service_role key here or anywhere in frontend code.
 */
const SUPABASE_URL = "https://pgrizvavodkksfeaahcl.supabase.co";
const SUPABASE_ANON_KEY = "sb_publishable_zO0oEMOtiebV7WZJ-gsLEw_tBBKArdg";


const supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: false,
  },
});
 
const AUTH_EMAIL_DOMAIN = "msgr.local";
 
function permanentIdToAuthEmail(permanentUserId) {
  return `${permanentUserId.toLowerCase()}@${AUTH_EMAIL_DOMAIN}`;
}
 
/**
 * Registers a brand new account:
 *  1. Reserve a unique Permanent User ID from the database function
 *     (server-side, collision-safe — see schema.sql section 4).
 *  2. Generate this device's E2EE keypair (crypto.js). The private key
 *     stays on-device; only the public key is uploaded.
 *  3. Create the Supabase Auth user with the synthetic email + the
 *     user's chosen password.
 *  4. Insert the profile row (name, permanent_user_id, icon_id,
 *     public_key). RLS only allows inserting a row whose id matches
 *     the caller's own auth uid, so this can only ever create your own
 *     profile.
 * Throws a user-friendly Error on any failure; nothing partial is left
 * silently — if profile creation fails after auth signup, we surface a
 * clear error asking the user to contact support / retry, since a
 * client cannot roll back an auth.users row without the service role
 * key (see README.md).
 */
async function registerAccount(name, password) {
  const trimmedName = name.trim();
  if (trimmedName.length < 1 || trimmedName.length > 40) {
    throw new Error("Name must be between 1 and 40 characters.");
  }
  if (password.length < 8) {
    throw new Error("Password must be at least 8 characters.");
  }
 
  const { data: idData, error: idError } = await supabaseClient.rpc(
    "generate_permanent_user_id"
  );
  if (idError || !idData) {
    throw new Error("Could not generate an account ID. Please try again.");
  }
  const permanentUserId = idData;
  const authEmail = permanentIdToAuthEmail(permanentUserId);
 
  const { data: signUpData, error: signUpError } = await supabaseClient.auth.signUp({
    email: authEmail,
    password,
  });
  if (signUpError || !signUpData.user) {
    if (signUpError && /already registered/i.test(signUpError.message)) {
      // Extremely unlikely (would require the generated id to collide
      // right after the uniqueness check above), but handle it cleanly.
      throw new Error("That account ID was just taken. Please try again.");
    }
    throw new Error("Could not create your account. Please try again.");
  }
 
  const publicKeyJson = await window.MessengerCrypto.generateAndStoreKeyPair(signUpData.user.id);
  const iconId = Math.floor(Math.random() * 8);
 
  const { error: profileError } = await supabaseClient.from("profiles").insert({
    id: signUpData.user.id,
    permanent_user_id: permanentUserId,
    name: trimmedName,
    icon_id: iconId,
    public_key: publicKeyJson,
  });
 
  if (profileError) {
    throw new Error(
      "Account created but profile setup failed. Please try logging in, or contact support."
    );
  }
 
  return { permanentUserId, name: trimmedName };
}
 
/**
 * Logs in with a Permanent User ID + password.
 * Looks up whether the id exists first purely to give a clean
 * "User not found" message instead of a generic auth error — the real
 * security boundary is still the password check inside signInWithPassword.
 */
async function loginWithUserId(permanentUserId, password) {
  const normalizedId = permanentUserId.trim().toUpperCase();
 
  const { data: exists, error: existsError } = await supabaseClient.rpc(
    "permanent_user_id_exists",
    { pid: normalizedId }
  );
  if (existsError) {
    throw new Error("Network error. Please try again.");
  }
  if (!exists) {
    throw new Error("User ID not found.");
  }
 
  const authEmail = permanentIdToAuthEmail(normalizedId);
  const { data, error } = await supabaseClient.auth.signInWithPassword({
    email: authEmail,
    password,
  });
 
  if (error) {
    throw new Error("Incorrect User ID or password.");
  }
 
  return data;
}
 
async function logout() {
  await supabaseClient.auth.signOut();
}
 
async function getCurrentSession() {
  const { data } = await supabaseClient.auth.getSession();
  return data.session;
}
 
/**
 * Calls the delete-account Edge Function (needs the service role key,
 * which only exists server-side — see supabase/functions/delete-account).
 */
async function deleteAccount() {
  const session = await getCurrentSession();
  if (!session) throw new Error("Session expired. Please log in again.");
 
  const { data, error } = await supabaseClient.functions.invoke("delete-account", {
    headers: { Authorization: `Bearer ${session.access_token}` },
  });
 
  if (error || !data?.success) {
    throw new Error("Account deletion failed. Please try again.");
  }
 
  await window.MessengerCrypto.clearDeviceKey(session.user.id);
  await supabaseClient.auth.signOut();
}
 
window.MessengerAuth = {
  supabaseClient,
  registerAccount,
  loginWithUserId,
  logout,
  getCurrentSession,
  deleteAccount,
};
 
