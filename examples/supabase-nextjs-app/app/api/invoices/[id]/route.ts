import { createClient } from "@supabase/supabase-js";

const admin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
);

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const { data } = await admin.from("invoices").select("*").eq("id", params.id).single();
  return Response.json(data);
}
