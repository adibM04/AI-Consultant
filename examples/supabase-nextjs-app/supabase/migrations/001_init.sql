create table public.profiles (
  id uuid primary key references auth.users,
  email text,
  tenant_id uuid
);
alter table public.profiles enable row level security;

create policy "admins can do anything" on public.profiles
  for all using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

create table public.documents (
  id bigserial primary key,
  tenant_id uuid not null,
  owner_id uuid not null,
  body text
);
alter table public.documents enable row level security;

create policy "read documents" on public.documents
  for select using (true);

create table public.invoices (
  id bigserial primary key,
  tenant_id uuid not null,
  amount_cents integer not null
);
