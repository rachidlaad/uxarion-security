create extension if not exists pgcrypto;

create table if not exists public.uxarion_telemetry_events (
    id uuid primary key default gen_random_uuid(),
    received_at timestamptz not null default now(),
    install_id text not null check (char_length(install_id) between 1 and 128),
    event_name text not null check (
        event_name in ('app_opened', 'session_started', 'report_generated')
    ),
    app_version text not null check (char_length(app_version) between 1 and 64),
    os text not null check (char_length(os) between 1 and 32),
    arch text not null check (char_length(arch) between 1 and 32),
    install_channel text not null check (
        install_channel in ('bun', 'npm', 'direct')
    ),
    sent_at bigint not null,
    properties jsonb not null default '{}'::jsonb
);

create index if not exists uxarion_telemetry_events_received_at_idx
    on public.uxarion_telemetry_events (received_at desc);

create index if not exists uxarion_telemetry_events_event_name_received_at_idx
    on public.uxarion_telemetry_events (event_name, received_at desc);

create index if not exists uxarion_telemetry_events_install_id_received_at_idx
    on public.uxarion_telemetry_events (install_id, received_at desc);

create index if not exists uxarion_telemetry_events_properties_gin_idx
    on public.uxarion_telemetry_events using gin (properties);

alter table public.uxarion_telemetry_events enable row level security;

comment on table public.uxarion_telemetry_events is
    'Anonymous product telemetry events emitted by Uxarion clients.';
