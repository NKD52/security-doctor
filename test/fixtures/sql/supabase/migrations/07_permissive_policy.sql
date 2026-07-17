CREATE POLICY "Permissive read" ON public.orders FOR SELECT USING (true);
CREATE POLICY "Permissive write" ON public.orders FOR INSERT WITH CHECK (true);
CREATE POLICY "Secure read" ON public.orders FOR SELECT USING (auth.uid() = user_id);
