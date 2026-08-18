export async function GET(req: Request, { params }: { params: { id: string } }) {
  const auth = await withApiAuth(req);
  const { data } = await supabase
    .from('members').select('*')
    .eq('id', params.id)
    .eq('organization_id', auth.organizationId)   // ← tenant-scoped ✓
    .single();
  return Response.json(data);
}
