-- Blank Config.Env in every container inspect response the proxy returns (docker-api.cfg).
--
-- cAdvisor needs /containers/<id>/json for the PID, labels, image and storage driver; it reads
-- Env only for names passed in --docker_env_metadata_whitelist, which Chronicle never sets.
-- One-shot jobs (config-guard, db-init, migrate, restore, monitoring-config, secrets-init)
-- still carry credentials in their environment, so the proxy must not hand them out.
--
-- Fails closed: when the body is incomplete or the array cannot be delimited, the response
-- is replaced by an error instead of being passed through.

-- Index just past the `]` that closes the JSON string array opening at `open` (the `[`),
-- or nil when the text ends first.
local function array_end(body, open)
  local i, n, in_string = open + 1, #body, false
  while i <= n do
    local c = body:sub(i, i)
    if in_string then
      if c == "\\" then
        i = i + 1
      elseif c == '"' then
        in_string = false
      end
    elseif c == '"' then
      in_string = true
    elseif c == "]" then
      return i + 1
    elseif c == "[" or c == "{" then
      return nil -- Env is a flat array of strings; anything else is not the shape we know
    end
    i = i + 1
  end
  return nil
end

local function strip_env(body)
  local out, position = {}, 1
  while true do
    local key_start, key_end = body:find('"Env"%s*:%s*', position)
    if not key_start then
      out[#out + 1] = body:sub(position)
      return table.concat(out)
    end
    local value = body:sub(key_end + 1, key_end + 1)
    if value == "[" then
      local close = array_end(body, key_end + 1)
      if not close then
        return nil
      end
      out[#out + 1] = body:sub(position, key_end) .. "[]"
      position = close
    elseif body:sub(key_end + 1, key_end + 4) == "null" then
      out[#out + 1] = body:sub(position, key_end + 4)
      position = key_end + 5
    else
      return nil
    end
  end
end

-- Runs after `http-response wait-for-body`, so res.body holds the whole response; it is
-- answered again with the blanked body, which ends the response rules. docker-api.cfg
-- returns 502 on the next line, so an error or a truncated body here fails closed.
local function action(txn)
  local body = txn.f:res_body()
  if body == nil or not body:match("^%s*{") or not body:match("}%s*$") then
    return -- empty or truncated (larger than tune.bufsize)
  end
  local stripped = strip_env(body)
  if stripped == nil then
    return
  end
  local content_type = "application/json"
  local headers = txn.http:res_get_headers()
  if headers["content-type"] and headers["content-type"][0] then
    content_type = headers["content-type"][0]
  end
  local reply = txn:reply({ status = txn.sf:status(), body = stripped })
  reply:add_header("content-type", content_type)
  txn:done(reply)
end

if core then -- absent when a test loads this file with a plain Lua interpreter
  core.register_action("chronicle_strip_env", { "http-res" }, action)
end

-- Exposed for tests run with a plain Lua interpreter (tests/selfhost-py/test_egress.py).
return { strip_env = strip_env }
