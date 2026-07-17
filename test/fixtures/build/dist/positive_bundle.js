const config = { supabaseUrl: "https://xyz.supabase.co", anonKey: "123" };
function updateRole(userId) {
  return supabase.from('users').update({ role: 'admin' }).eq('id', userId);
}
