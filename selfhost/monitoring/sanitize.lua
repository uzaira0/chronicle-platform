local function token(value, limit)
  local text = value == nil and "" or tostring(value)
  text = string.gsub(text, "[^%w_.:-]", "_")
  if string.len(text) > limit then text = string.sub(text, 1, limit) end
  return text
end

local function normalized_route(value)
  local route = tostring(value or "")
  route = string.gsub(route, "?.*$", "")
  route = string.gsub(route, "/%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x", "/{id}")
  route = string.gsub(route, "/%d+", "/{id}")
  local resources = {"study", "studies", "participant", "participants", "device", "devices", "user", "users", "export", "exports"}
  for _, resource in ipairs(resources) do
    route = string.gsub(route, "/" .. resource .. "/[^/]+", "/" .. resource .. "/{id}")
  end
  route = string.gsub(route, "/[^/]*[@%%=][^/]*", "/{id}")
  if string.len(route) > 160 then route = string.sub(route, 1, 160) end
  return route
end

local function nested(record, object_name, field_name)
  local object = record[object_name]
  if type(object) == "table" then return object[field_name] end
  return nil
end

function sanitize(tag, timestamp, record)
  local source = record
  -- Unstructured input is intentionally not decoded or retained. Known JSON and PostgreSQL
  -- formats are parsed by Fluent Bit before this filter; everything else becomes a safe,
  -- generic event instead of leaking a raw message.
  if type(record["log"]) == "string" then
    source = { message = record["log"] }
  end
  local service = string.match(tag, "^chronicle%.([%w_-]+)") or "unknown"
  local duration_ms = tonumber(source["durationMs"] or source["duration_ms"])
  if duration_ms == nil and tonumber(source["duration"]) ~= nil then
    duration_ms = tonumber(source["duration"]) * 1000
  end
  local event_timestamp = source["timestamp"] or source["@timestamp"] or source["ts"]
  if event_timestamp == nil and tonumber(source["timestamp_seconds"]) ~= nil then
    event_timestamp = tonumber(source["timestamp_seconds"])
  end
  local out = {
    timestamp = event_timestamp or os.date("!%Y-%m-%dT%H:%M:%SZ"),
    service = service,
    stream = service == "audit" and "audit" or "operational",
    severity = string.upper(token(source["level"] or source["severity"] or (service == "postgres" and "UNPARSED" or "INFO"), 16)),
    request_id = token(source["requestId"] or source["request_id"], 64),
    error_id = token(source["errorId"] or source["error_id"], 64),
    operation = token(source["operation"] or source["eventType"] or source["action"], 64),
    result = token(source["result"] or source["outcome"] or source["success"], 32),
    failure_category = token(source["failureCategory"] or source["failure_category"], 48),
    release_version = token(source["releaseVersion"] or source["release_version"], 48),
    status = token(source["status"] or source["status_code"], 16),
    method = token(source["httpMethod"] or source["method"] or nested(source, "request", "method"), 12),
    route = normalized_route(source["httpPath"] or source["route"] or nested(source, "request", "uri")),
    duration_ms = duration_ms,
    sqlstate = token(source["sqlstate"] or source["sqlState"], 5),
    exception_class = token(source["exceptionClass"] or source["exception_class"], 128)
  }
  -- VictoriaLogs requires a message field. Build it only from the allowlisted,
  -- bounded categories above; never forward the source message or stack trace.
  out["message"] = table.concat({out["service"], token(out["severity"], 16), out["operation"], out["result"], out["status"], out["exception_class"]}, " ")
  return 1, timestamp, out
end
