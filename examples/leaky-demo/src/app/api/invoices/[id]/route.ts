// A typical AI-generated handler. Looks fine. Leaks across tenants.
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const auth = await withApiAuth(req);            // authenticated ✓
  const { data } = await supabase
    .from('invoices').select('*')
    .eq('id', params.id)                          // ← filtered by id ALONE
    .single();
  return Response.json(data);                     // any tenant can read any invoice
}
