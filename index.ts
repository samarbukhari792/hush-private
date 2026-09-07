// supabase/functions/delete-account/index.ts
//
// WHY THIS FILE EXISTS (extra file, explained per spec section 20):
// Deleting a Supabase Auth user requires the service_role key. That key
// must never be shipped to the browser (spec section 14), so account
// deletion cannot be done directly from app.js. This Edge Function runs
// on Supabase's servers, holds the service_role key only as a server-side
// secret, and does the deletion on behalf of the caller after verifying
// their identity from their own session token.
//
// Deploy with:
//   supabase functions deploy delete-account
//
// The SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY env vars are provided
// automatically by Supabase in the Edge Function runtime — you do not
// set them yourself.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "Missing authorization header." }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Client bound to the CALLER's own JWT — used only to find out who
    // is calling. This never uses the service role key.
    const callerClient = createClient(SUPABASE_URL, authHeader.replace("Bearer ", ""), {
      global: { headers: { Authorization: authHeader } },
    });

    const {
      data: { user },
      error: userError,
    } = await callerClient.auth.getUser();

    if (userError || !user) {
      return new Response(JSON.stringify({ error: "Invalid or expired session." }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Admin client — service role key never leaves this server function.
    const adminClient = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

    // Deleting the auth user cascades to public.profiles (FK ON DELETE
    // CASCADE), which in turn cascades to public.messages (FK ON DELETE
    // CASCADE on both sender_id and receiver_id), so a single call here
    // removes the account, its profile, and every message it sent or
    // received. This is transactional at the Postgres level because the
    // cascades run inside the database's own delete, not as separate
    // client-side steps.
    const { error: deleteError } = await adminClient.auth.admin.deleteUser(user.id);

    if (deleteError) {
      console.error("delete-account: admin.deleteUser failed", deleteError);
      return new Response(JSON.stringify({ error: "Account deletion failed. Please try again." }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    console.error("delete-account: unexpected error", err);
    return new Response(JSON.stringify({ error: "Account deletion failed. Please try again." }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
