import "@supabase/functions-js/edge-runtime.d.ts"
import { createClient } from "npm:@supabase/supabase-js@2"

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
}

const allowedEvents = new Set(["app_opened", "session_started", "report_generated"])
const allowedInstallChannels = new Set(["bun", "npm", "direct"])
const maxEventsPerRequest = 20
const maxInstallIdLength = 128
const maxStringLength = 64
const maxPropertiesBytes = 8 * 1024

type TelemetryEvent = {
  eventName: string
  installId: string
  appVersion: string
  os: string
  arch: string
  installChannel: string
  sentAt: number
  properties: unknown
}

function jsonResponse(status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: corsHeaders,
  })
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function isNonEmptyString(value: unknown, maxLength = maxStringLength): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength
}

function validateEvent(value: unknown): value is TelemetryEvent {
  if (!isPlainObject(value)) {
    return false
  }

  if (!isNonEmptyString(value.eventName) || !allowedEvents.has(value.eventName)) {
    return false
  }

  if (
    !isNonEmptyString(value.installId, maxInstallIdLength) ||
    !isNonEmptyString(value.appVersion) ||
    !isNonEmptyString(value.os, 32) ||
    !isNonEmptyString(value.arch, 32) ||
    !isNonEmptyString(value.installChannel) ||
    !allowedInstallChannels.has(value.installChannel)
  ) {
    return false
  }

  if (!Number.isInteger(value.sentAt) || value.sentAt <= 0) {
    return false
  }

  if (!isPlainObject(value.properties)) {
    return false
  }

  const propertiesBytes = new TextEncoder().encode(JSON.stringify(value.properties)).length
  if (propertiesBytes > maxPropertiesBytes) {
    return false
  }

  return true
}

function sanitizedRows(events: TelemetryEvent[]) {
  return events.map((event) => ({
    install_id: event.installId,
    event_name: event.eventName,
    app_version: event.appVersion,
    os: event.os,
    arch: event.arch,
    install_channel: event.installChannel,
    sent_at: event.sentAt,
    properties: event.properties,
  }))
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders })
  }

  if (req.method !== "POST") {
    return jsonResponse(405, { error: "method_not_allowed" })
  }

  let payload: unknown
  try {
    payload = await req.json()
  } catch {
    return jsonResponse(400, { error: "invalid_json" })
  }

  if (!isPlainObject(payload) || !Array.isArray(payload.events)) {
    return jsonResponse(400, { error: "invalid_payload" })
  }

  if (payload.events.length === 0 || payload.events.length > maxEventsPerRequest) {
    return jsonResponse(400, { error: "invalid_event_batch_size" })
  }

  if (!payload.events.every(validateEvent)) {
    return jsonResponse(400, { error: "invalid_event_shape" })
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL")
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")
  if (!supabaseUrl || !serviceRoleKey) {
    return jsonResponse(500, { error: "missing_supabase_env" })
  }

  const supabase = createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  })

  const { error } = await supabase
    .from("uxarion_telemetry_events")
    .insert(sanitizedRows(payload.events))

  if (error) {
    console.error("failed to insert uxarion telemetry events", error)
    return jsonResponse(500, { error: "insert_failed" })
  }

  return jsonResponse(202, { accepted: payload.events.length })
})
