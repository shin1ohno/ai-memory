#!/usr/bin/env ruby
# frozen_string_literal: true

# Mirror the harness-native file memory (~/.claude/projects/<slug>/memory/*.md)
# into a memory-v2 MCP store, so the same knowledge is reachable both from the
# auto-loaded MEMORY.md index AND from `recall` / the box's autonomous agents.
#
# Modes:
#   (no args)                  PostToolUse hook. stdin carries the tool payload;
#                              the written file is mirrored when it is a memory
#                              note. Failures come back to the agent as
#                              hookSpecificOutput.additionalContext.
#   --sweep --session-start    SessionStart hook. Reconciles every note within a
#                              40 s budget (state is saved per item, so the next
#                              start resumes), and refuses a first bulk import
#                              (no state file and > 20 notes to send) — that
#                              one is run by hand. Failures, including an
#                              unresolvable server or a failed token fetch, come
#                              back as additionalContext.
#   --sweep [--dry-run]        Manual reconcile: no budget, no bulk guard. The
#                              one-time import on a new host.
#   --check                    Live round-trip gate for the client_credentials
#                              config: token claims, ingest + forget (by id and
#                              by dataset/doc_key) of <host>/_selftest/roundtrip,
#                              and three calls the server policy must deny.
#                              Run it the way the hook runs, through ruby-shim
#                              in a minimal environment:
#                                env -i HOME="$HOME" ~/.claude/hooks/ruby-shim \
#                                  ~/.claude/hooks/mirror-file-memory.rb --check
#                              Exits non-zero on any failed assertion.
#
# Why a script and not the MCP tools: the write must not depend on the session's
# MCP client (a) because a hook has no access to it, and (b) because that client
# is the component that breaks — 2026-08-17 it answered every
# `mcp__memory-work__*` call with `DCR rejected (HTTP 401) invalid_token` while
# raw JSON-RPC against the same endpoint with the same headersHelper token
# worked. This path talks to the server directly.
#
# Primitive is `ingest`, not `remember`: ingest upserts by (dataset, doc_key), so
# a re-run supersedes its own previous version instead of piling up duplicates,
# and it does not depend on the keeper/reconciler. Deletions use forget by
# (dataset, doc_key) too, so they work even when an ingest returned only a
# job_id and no doc_id was ever recorded.
#
# Config — ~/.claude/memory-mirror.json. Absent or enabled:false => silent
# no-op; the public claude-code cookbook ships NO config. Two shapes:
#
#   Server-name form (the work overlay):
#     {"server": "memory-work", "dataset": "file-memory", "enabled": true}
#     `server` names an mcpServers entry in ~/.claude.json with an http url; its
#     `headersHelper` (when present) supplies the Authorization header.
#
#   client_credentials form (personal hosts, written by cookbooks/memory-mirror):
#     {"enabled": true, "dataset": "file-memory", "host": "pro-dev",
#      "url": "https://mcp.ohno.be/memory/mcp",
#      "auth": {"type": "client_credentials",
#               "token_url": "https://mcp.ohno.be/oauth2/token",
#               "audience": "memory",
#               "credentials_file": "~/.config/memory-mirror/client.env"}}
#     A token is fetched per run (client_secret_basic + audience, no cache).
#     `url` and `token_url` must be https (plain http only to 127.0.0.1, for
#     tests). The credentials file carries MEMORY_MIRROR_CLIENT_ID= and
#     MEMORY_MIRROR_CLIENT_SECRET=, must be mode 0600, and is checked locally on
#     every sweep. A redirect is an error: the server answers 307 when the url
#     carries a trailing slash.
#
#   `host` (optional, both forms) is the doc_key prefix; it defaults to the
#   short hostname, which is not stable on macOS.
#
# doc_key = <host>/<project-slug>/<note basename without .md>. An oversized note
# is skipped with a WARN and reported to the agent until it shrinks: in the
# client_credentials form, a document past 45,000 characters (the server
# policy's cap for a restricted client); in the server-name form, a note body
# past 512 KB (that store has no such policy).
#
# State — ~/.claude/memory-mirror-state.json: doc_key => {sha256, doc_id, ...},
#   written after every item. sha match => no HTTP at all (a steady-state sweep
#   sends nothing). A state entry whose file has disappeared => forget, so
#   deletions propagate. Only a sweep creates the file (see State).
#
# Never disturbs the session: hook modes always exit 0 and log one line per
# event to ~/.claude/memory-mirror.log. Secrets, request/response bodies,
# headers and token responses are never logged or surfaced.

require "digest"
require "fileutils"
require "json"
require "net/http"
require "open3"
require "socket"
require "uri"

# Memory notes are mostly Japanese. Without a UTF-8 locale the default external
# encoding is US-ASCII, so JSON.parse($stdin.read) raises before the config is
# even read and File.read tags note bodies as US-ASCII. ruby-shim already passes
# -E UTF-8; pinning it here too keeps a direct `ruby mirror-file-memory.rb
# --sweep` from a locale-less shell working.
Encoding.default_external = Encoding::UTF_8

HOME         = Dir.home
CONFIG_PATH  = ENV["MEMORY_MIRROR_CONFIG"]       || File.join(HOME, ".claude", "memory-mirror.json")
STATE_PATH   = ENV["MEMORY_MIRROR_STATE"]        || File.join(HOME, ".claude", "memory-mirror-state.json")
LOCK_PATH    = ENV["MEMORY_MIRROR_LOCK"]         || File.join(HOME, ".claude", "memory-mirror.lock")
LOG_PATH     = ENV["MEMORY_MIRROR_LOG"]          || File.join(HOME, ".claude", "memory-mirror.log")
CLAUDE_JSON  = ENV["MEMORY_MIRROR_CLAUDE_JSON"]  || File.join(HOME, ".claude.json")
PROJECTS_DIR = ENV["MEMORY_MIRROR_PROJECTS_DIR"] || File.join(HOME, ".claude", "projects")
DEFAULT_HOST = ENV["MEMORY_MIRROR_HOST"]         || Socket.gethostname.to_s.split(".").first

INDEX_BASENAME   = "MEMORY.md"
# Size caps differ by config form. client_credentials: the server policy refuses
# a restricted client's ingest document past this many characters. Server-name
# form: that store has no such policy, so only the hook's original guard applies
# — a memory note is a few KB, and a note body past 512 KB is not one.
MAX_CHARS        = 45_000
MAX_BYTES        = 512 * 1024
OPEN_TIMEOUT     = 2
READ_TIMEOUT     = 20
HELPER_TIMEOUT   = 10
FIRST_BULK_LIMIT = 20
# SessionStart blocks the session, so the automatic sweep stops starting new
# items after this many seconds; the remainder goes on the next start. The
# settings.json hook timeout leaves room for one in-flight request past it.
SESSION_BUDGET   = Float(ENV["MEMORY_MIRROR_SESSION_BUDGET"].to_s, exception: false) || 40.0
STARTED_AT       = Process.clock_gettime(Process::CLOCK_MONOTONIC)

CLIENT_ID_KEY      = "MEMORY_MIRROR_CLIENT_ID"
CLIENT_SECRET_KEY  = "MEMORY_MIRROR_CLIENT_SECRET"
SELFTEST_KEY       = "_selftest/roundtrip"
DENIED_DATASET     = "memory-mirror-selftest-denied"
EXPECTED_TOKEN_TTL = 3600

# A failure whose message is safe to log and to show the agent: it never
# carries a secret, a header, or a request/response body.
class MirrorError < StandardError; end

# A tools/call that the server answered with isError (or a JSON-RPC error).
# `text` is the server's own error text, shortened to its first line.
class ToolCallError < MirrorError
  attr_reader :text

  def initialize(tool, text)
    @text = text
    super("#{tool}: #{text}")
  end
end

def log(level, msg)
  FileUtils.mkdir_p(File.dirname(LOG_PATH))
  File.open(LOG_PATH, "a") { |f| f.puts("#{Time.now.utc.strftime('%FT%TZ')} #{level} #{msg}") }
rescue StandardError
  nil
end

def short(text)
  text.to_s.lines.first.to_s.strip[0, 160]
end

def elapsed
  Process.clock_gettime(Process::CLOCK_MONOTONIC) - STARTED_AT
end

# Collects what the agent must hear about and emits it once, in the shape the
# invoking hook event expects (plain stderr for manual runs).
class Report
  attr_reader :problems

  def initialize(event)
    @event = event
    @problems = []
    @notes = []
  end

  def problem(msg)
    @problems << msg
    log("WARN", msg)
  end

  def note(msg)
    @notes << msg
    log("INFO", msg)
  end

  def emit
    return if @problems.empty? && @notes.empty?

    text = "file-memory mirror: #{(@problems + @notes).join(' ')}"
    unless @problems.empty?
      text += " Knowledge saved to ~/.claude/projects/*/memory/ is NOT searchable via recall " \
              "until this clears. See #{LOG_PATH}."
    end

    if @event
      puts JSON.generate("hookSpecificOutput" => { "hookEventName" => @event, "additionalContext" => text })
    else
      warn text
    end
  end
end

# --- config ------------------------------------------------------------------

# nil => the mirror is off (no file, or enabled is not true). A file that exists
# but cannot be understood raises, so the caller can tell the agent.
def load_config
  return nil unless File.exist?(CONFIG_PATH)

  begin
    cfg = JSON.parse(File.read(CONFIG_PATH))
  rescue JSON::ParserError, SystemCallError => e
    raise MirrorError, "config #{CONFIG_PATH} is unreadable (#{e.class})"
  end
  raise MirrorError, "config #{CONFIG_PATH} is not a JSON object" unless cfg.is_a?(Hash)
  return nil unless cfg["enabled"] == true

  host = cfg["host"].to_s.strip
  host = DEFAULT_HOST.to_s if host.empty?
  raise MirrorError, "config host #{host.inspect} must be a non-empty name without '/'" if host.empty? || host.include?("/")

  base = { dataset: cfg["dataset"].to_s.empty? ? "file-memory" : cfg["dataset"].to_s, host: host }

  unless cfg["server"].to_s.empty?
    return base.merge(kind: :server, server: cfg["server"].to_s, label: "the #{cfg['server']} store")
  end

  raise MirrorError, "config #{CONFIG_PATH} has neither `server` nor `url`" if cfg["url"].to_s.empty?

  auth = cfg["auth"]
  unless auth.is_a?(Hash) && auth["type"] == "client_credentials"
    raise MirrorError, "config #{CONFIG_PATH}: `auth.type` must be \"client_credentials\""
  end
  raise MirrorError, "config #{CONFIG_PATH}: `auth.audience` is empty" if auth["audience"].to_s.empty?
  raise MirrorError, "config #{CONFIG_PATH}: `auth.credentials_file` is empty" if auth["credentials_file"].to_s.empty?

  base.merge(
    kind: :client_credentials,
    url: checked_url(cfg["url"], "url"),
    token_url: checked_url(auth["token_url"], "auth.token_url"),
    audience: auth["audience"].to_s,
    credentials_file: File.expand_path(auth["credentials_file"].to_s),
    label: "the memory store at #{cfg['url']}",
  )
end

# The bearer token and the client secret travel on these URLs, so plain http is
# refused. 127.0.0.1 is the one exception, for the black-box tests.
def checked_url(raw, field)
  uri = URI.parse(raw.to_s)
  secure = uri.scheme == "https" || (uri.scheme == "http" && uri.host == "127.0.0.1")
  raise MirrorError, "config `#{field}` must be an https:// URL (got #{uri.scheme.inspect})" unless secure
  raise MirrorError, "config `#{field}` has no host" if uri.host.to_s.empty?

  raw.to_s
rescue URI::InvalidURIError
  raise MirrorError, "config `#{field}` is not a valid URL"
end

# Local-only validation of the client credentials file: it exists, carries both
# keys, and grants nothing to group/other. Messages never include a value.
def read_credentials(path)
  raise MirrorError, "credentials file #{path} is missing" unless File.exist?(path)

  st = File.stat(path)
  raise MirrorError, "credentials file #{path} is not a regular file" unless st.file?

  perm = st.mode & 0o777
  if perm & 0o077 != 0
    raise MirrorError, "credentials file #{path} has mode 0#{perm.to_s(8)}; it must be 0600 (chmod 600 #{path})"
  end

  values = {}
  File.foreach(path) do |line|
    next unless line.chomp =~ /\A\s*(#{CLIENT_ID_KEY}|#{CLIENT_SECRET_KEY})=(.*)\z/

    values[$1] = $2.strip
  end
  missing = [CLIENT_ID_KEY, CLIENT_SECRET_KEY].select { |k| values[k].to_s.empty? }
  raise MirrorError, "credentials file #{path} lacks #{missing.join(' and ')}" unless missing.empty?

  [values[CLIENT_ID_KEY], values[CLIENT_SECRET_KEY]]
rescue SystemCallError => e
  raise MirrorError, "credentials file #{path} is unreadable (#{e.class})"
end

# --- HTTP ------------------------------------------------------------------

def http_for(uri)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == "https")
  http.open_timeout = OPEN_TIMEOUT
  http.read_timeout = READ_TIMEOUT
  http
end

# Net::HTTP does not follow redirects, and following one would resend the
# bearer token to wherever it points. A 3xx here has one known cause.
def redirect_error(what, code)
  MirrorError.new("#{what} answered HTTP #{code} (redirect): the configured URL most likely has a " \
                  "trailing slash; use it exactly as documented (.../memory/mcp, no trailing '/')")
end

def status_error(what, code)
  hint =
    case code
    when 401 then " (token rejected: expired, wrong audience, or bad signature)"
    when 403 then " (client or audience not allowed by the proxy)"
    else ""
    end
  MirrorError.new("#{what} answered HTTP #{code}#{hint}")
end

# An OAuth error response carries a short machine code (invalid_client, ...).
# That code — and nothing else from the body — is safe to report.
def oauth_error_code(body)
  code = JSON.parse(body.to_s)["error"].to_s
  code.match?(/\A[a-z_]{1,40}\z/) ? " (#{code})" : ""
rescue StandardError
  ""
end

def fetch_token(config, client_id, secret)
  uri = URI.parse(config[:token_url])
  req = Net::HTTP::Post.new(uri.request_uri)
  basic = ["#{URI.encode_www_form_component(client_id)}:#{URI.encode_www_form_component(secret)}"].pack("m0")
  req["authorization"] = "Basic #{basic}"
  req["accept"] = "application/json"
  req.set_form_data("grant_type" => "client_credentials", "audience" => config[:audience])

  begin
    res = http_for(uri).start { |conn| conn.request(req) }
  rescue StandardError => e
    raise MirrorError, "token endpoint unreachable (#{e.class}: #{short(e.message)})"
  end

  code = res.code.to_i
  raise redirect_error("token endpoint", code) if code.between?(300, 399)
  raise MirrorError, "token endpoint answered HTTP #{code}#{oauth_error_code(res.body)}" unless code == 200

  token = begin
    JSON.parse(res.body.to_s)["access_token"].to_s
  rescue StandardError
    ""
  end
  raise MirrorError, "token endpoint answered 200 without an access_token" if token.empty?

  token
end

# The endpoint and its auth are read from the live MCP registration rather than
# hardcoded, so this stays generic across hosts (and follows the store if its
# port or audience changes).
def resolve_server(name)
  entry = begin
    JSON.parse(File.read(CLAUDE_JSON)).dig("mcpServers", name)
  rescue JSON::ParserError, SystemCallError => e
    raise MirrorError, "#{CLAUDE_JSON} is unreadable (#{e.class})"
  end
  raise MirrorError, "no mcpServers entry named #{name.inspect} in #{CLAUDE_JSON}" if entry.nil?

  url = entry["url"].to_s
  raise MirrorError, "mcpServers entry #{name} has no url" if url.empty?

  headers = {}
  helper = entry["headersHelper"].to_s
  unless helper.empty?
    out, status = begin
      with_timeout(HELPER_TIMEOUT) { Open3.capture2(helper) }
    rescue SystemCallError => e
      raise MirrorError, "headersHelper #{helper} could not run (#{e.class})"
    end
    raise MirrorError, "headersHelper #{helper} exited #{status.exitstatus}" unless status.success?

    # The helper's stdout IS the credential; a parse error would quote it.
    parsed = begin
      JSON.parse(out)
    rescue JSON::ParserError
      nil
    end
    raise MirrorError, "headersHelper #{helper} did not emit a JSON object" unless parsed.is_a?(Hash)

    parsed.each { |k, v| headers[k.to_s] = v.to_s }
  end

  { url: url, headers: headers }
end

def with_timeout(seconds)
  # Timeout.timeout cannot interrupt a blocking waitpid on every ruby build, so
  # the helper is fenced by its own alarm-free guard: run it in a thread and give
  # up on the result if it overruns (the child is short-lived curl).
  thread = Thread.new { yield }
  raise MirrorError, "headersHelper timed out after #{seconds}s" unless thread.join(seconds)

  thread.value
end

# One token per run; nothing is cached on disk.
def connect(config)
  if config[:kind] == :server
    server = resolve_server(config[:server])
    client = McpClient.new(server[:url], server[:headers])
  else
    client_id, secret = read_credentials(config[:credentials_file])
    token = fetch_token(config, client_id, secret)
    client = McpClient.new(config[:url], { "authorization" => "Bearer #{token}" })
  end
  client.connect!
  client
end

# --- MCP client (stateful streamable HTTP, SSE-framed responses) -------------

class McpClient
  PROTOCOL = "2025-06-18"

  def initialize(url, headers)
    @uri = URI.parse(url)
    @headers = headers
    @id = 0
  end

  def connect!
    return @session if @session

    body = jsonrpc("initialize", {
      "protocolVersion" => PROTOCOL,
      "capabilities" => {},
      "clientInfo" => { "name" => "memory-mirror", "version" => "2" },
    }, id: true)

    response = request(body)
    check_status("initialize", response)

    @session = response["mcp-session-id"].to_s
    raise MirrorError, "initialize returned no mcp-session-id" if @session.empty?

    request(jsonrpc("notifications/initialized", nil))
    @session
  end

  def call(tool, arguments)
    connect!
    response = request(jsonrpc("tools/call", { "name" => tool, "arguments" => arguments }, id: true))
    check_status(tool, response)
    msg = parse_payload(response.body)

    if msg["error"].is_a?(Hash)
      raise ToolCallError.new(tool, "JSON-RPC error #{msg['error']['code']}: #{short(msg['error']['message'])}")
    end

    result = msg["result"] || {}
    raise ToolCallError.new(tool, short(result.dig("content", 0, "text"))) if result["isError"]

    text = result.dig("content", 0, "text")
    return result if text.nil?

    begin
      JSON.parse(text)
    rescue JSON::ParserError
      text
    end
  end

  private

  def check_status(what, response)
    code = response.code.to_i
    return if code == 200
    raise redirect_error(what, code) if code.between?(300, 399)

    raise status_error(what, code)
  end

  def jsonrpc(method, params, id: false)
    body = { "jsonrpc" => "2.0", "method" => method }
    body["id"] = (@id += 1) if id
    body["params"] = params unless params.nil?
    body
  end

  def request(body)
    req = Net::HTTP::Post.new(@uri.request_uri)
    @headers.each { |k, v| req[k] = v }
    req["content-type"] = "application/json"
    req["accept"] = "application/json, text/event-stream"
    req["mcp-session-id"] = @session if @session
    req.body = JSON.generate(body)

    http_for(@uri).start { |conn| conn.request(req) }
  rescue StandardError => e
    raise MirrorError, "#{body['method']} failed (#{e.class}: #{short(e.message)})"
  end

  # Responses come back SSE-framed (`event: message` / `data: {...}`); a plain
  # JSON body is accepted too so this does not depend on the framing choice.
  def parse_payload(raw)
    text = raw.to_s
    candidates = text.lines.select { |l| l.start_with?("data:") }.map { |l| l.sub(/\Adata:\s*/, "") }
    candidates = [text] if candidates.empty?

    candidates.reverse_each do |chunk|
      begin
        parsed = JSON.parse(chunk)
      rescue JSON::ParserError
        next
      end
      return parsed if parsed.is_a?(Hash) && (parsed.key?("result") || parsed.key?("error"))
    end

    raise MirrorError, "unparsable MCP response (#{text.bytesize} bytes)"
  end
end

# --- memory-note identification --------------------------------------------

# Returns "<project-slug>/<basename>" for a memory note, nil for anything else.
def memory_note(path)
  return nil if path.to_s.empty?

  full = File.expand_path(path)
  root = File.expand_path(PROJECTS_DIR)
  return nil unless full.start_with?(root + File::SEPARATOR)

  parts = full[(root.length + 1)..].split(File::SEPARATOR)
  return nil unless parts.length == 3 && parts[1] == "memory"
  return nil unless parts[2].end_with?(".md")
  return nil if parts[2] == INDEX_BASENAME

  "#{parts[0]}/#{parts[2]}"
end

def doc_key(host, rel)
  slug, basename = rel.split("/", 2)
  "#{host}/#{slug}/#{File.basename(basename, '.md')}"
end

def note_paths
  Dir.glob(File.join(PROJECTS_DIR, "*", "memory", "*.md")).select { |p| memory_note(p) }.sort
end

# --- state ------------------------------------------------------------------

# Only a sweep creates the state file; the PostToolUse hook updates it once it
# exists but never creates it. "No state file" therefore means "no sweep has
# run on this host yet", which is what the first-bulk guard keys on — a single
# note written before the first manual sweep must not open the gate for the
# automatic sweep to push the whole backlog.
class State
  attr_reader :entries

  def initialize(create:)
    @existed = File.exist?(STATE_PATH)
    @create = create
    @entries = load
  end

  def existed?
    @existed
  end

  def save
    return unless @existed || @create

    FileUtils.mkdir_p(File.dirname(STATE_PATH))
    tmp = "#{STATE_PATH}.tmp"
    File.write(tmp, JSON.pretty_generate(@entries) + "\n")
    File.rename(tmp, STATE_PATH)
  rescue StandardError => e
    log("WARN", "state write failed: #{e.class}")
  end

  private

  def load
    return {} unless @existed

    parsed = JSON.parse(File.read(STATE_PATH))
    parsed.is_a?(Hash) ? parsed : {}
  rescue StandardError
    {}
  end
end

# One run at a time. A hook that loses the race exits immediately — the
# SessionStart sweep picks the file up, so nothing is lost by not waiting.
def with_lock
  FileUtils.mkdir_p(File.dirname(LOCK_PATH))
  File.open(LOCK_PATH, File::RDWR | File::CREAT, 0o600) do |f|
    unless f.flock(File::LOCK_EX | File::LOCK_NB)
      log("INFO", "another mirror run holds the lock; deferring to the next sweep")
      return nil
    end

    yield
  end
end

# --- operations -------------------------------------------------------------

# Reads a note once and decides what to do with it, before any network call.
def prepare_note(config, path, rel, state)
  body = File.read(path)
  key = doc_key(config[:host], rel)
  sha = Digest::SHA256.hexdigest(body)
  slug, = rel.split("/", 2)
  document = "<!-- claude-file-memory mirror -->\n" \
             "project: #{slug}\n" \
             "source_host: #{config[:host]}\n" \
             "source_path: #{path}\n\n" + body
  size = config[:kind] == :client_credentials ? document.length : body.bytesize
  status =
    if state.entries.dig(key, "sha256") == sha then :unchanged
    elsif size > size_limit(config) then :too_large
    else :send
    end
  { path: path, key: key, sha: sha, document: document, size: size, status: status }
end

def size_limit(config)
  config[:kind] == :client_credentials ? MAX_CHARS : MAX_BYTES
end

def size_unit(config)
  config[:kind] == :client_credentials ? "characters" : "bytes"
end

# Records the skip so a steady-state sweep stays offline, while every sweep
# still reports the note until it shrinks (see oversized_keys).
def record_too_large(config, note, state)
  state.entries[note[:key]] = {
    "sha256" => note[:sha],
    "skipped" => "too_large",
    "size" => "#{note[:size]} #{size_unit(config)}",
    "source_path" => note[:path],
  }
  state.save
  log("WARN", "skipped #{note[:key]}: #{note[:size]} #{size_unit(config)} exceeds #{size_limit(config)}")
end

def mirror_one(client, config, note, state)
  result = client.call("ingest", {
    "document" => note[:document],
    "dataset" => config[:dataset],
    "doc_key" => note[:key],
  })
  doc_id = result.is_a?(Hash) ? (result["doc_id"] || result["job_id"]) : nil

  state.entries[note[:key]] = {
    "sha256" => note[:sha],
    "doc_id" => doc_id,
    "source_path" => note[:path],
    "mirrored_at" => Time.now.utc.strftime("%FT%TZ"),
  }
  state.save
  log("INFO", "mirrored #{note[:key]} (doc_id=#{doc_id})")
end

def forget_one(client, config, key, state)
  result = client.call("forget", { "dataset" => config[:dataset], "doc_key" => key })
  count = result.is_a?(Hash) ? result["superseded_count"] : nil
  state.entries.delete(key)
  state.save
  log("INFO", "forgot #{key} (superseded_count=#{count}) — source file is gone")
end

def stale_keys(host, state, live_keys)
  state.entries.keys.select { |k| k.start_with?("#{host}/") && !live_keys.include?(k) }
end

def oversized_keys(state, live)
  live.keys.select { |k| state.entries.dig(k, "skipped") == "too_large" }
end

def report_oversized(report, config, keys)
  return if keys.empty?

  report.problem("#{keys.length} note(s) exceed #{size_limit(config)} #{size_unit(config)} and are not mirrored " \
                 "(#{keys.first(5).join(', ')}); split or shorten them.")
end

def print_dry_run(config, creds_problem, paths, pending, gone)
  target = config[:kind] == :server ? "server: #{config[:server]}" : "url: #{config[:url]}"
  puts "dataset: #{config[:dataset]}  #{target}  host: #{config[:host]}"
  puts "credentials: #{creds_problem || 'ok'}" if config[:kind] == :client_credentials
  puts "notes: #{paths.length}  to-ingest: #{pending.count { |n| n[:status] == :send }}  " \
       "too-large: #{pending.count { |n| n[:status] == :too_large }}  " \
       "unchanged: #{paths.length - pending.length}  to-forget: #{gone.length}"
  pending.each { |n| puts "  #{n[:status] == :send ? 'ingest' : 'TOOBIG'}  #{n[:key]}  <- #{n[:path]}" }
  gone.each    { |k| puts "  forget  #{k}" }
end

def sweep(config, mode, report)
  host = config[:host]
  paths = note_paths
  state = State.new(create: true)
  live = {}
  paths.each { |p| live[doc_key(host, memory_note(p))] = p }
  gone = stale_keys(host, state, live.keys)
  pending = paths.map { |p| prepare_note(config, p, memory_note(p), state) }.reject { |n| n[:status] == :unchanged }

  creds_problem = nil
  if config[:kind] == :client_credentials
    begin
      read_credentials(config[:credentials_file])
    rescue MirrorError => e
      creds_problem = e.message
    end
  end

  return print_dry_run(config, creds_problem, paths, pending, gone) if mode == :dry_run

  report.problem(creds_problem) if creds_problem
  too_large = pending.select { |n| n[:status] == :too_large }
  to_send = pending.select { |n| n[:status] == :send }

  # Checked before anything is recorded: writing even a too-large entry would
  # create the state file and disarm the guard for the next start.
  if mode == :session_start && !state.existed? && to_send.length + gone.length > FIRST_BULK_LIMIT
    report.problem("first sweep on this host would send #{to_send.length} notes, more than the " \
                   "#{FIRST_BULK_LIMIT} a session start sends on its own; nothing was sent. Run " \
                   "`ruby ~/.claude/hooks/mirror-file-memory.rb --sweep --dry-run`, then `--sweep`, once by hand.")
    return
  end

  too_large.each { |n| record_too_large(config, n, state) }

  # Steady state: return before connecting, so a session start does not mint a
  # token (or run a headersHelper) for nothing.
  if to_send.empty? && gone.empty?
    report_oversized(report, config, oversized_keys(state, live))
    log("INFO", "sweep: #{paths.length} notes, all up to date")
    return
  end

  return if creds_problem

  begin
    client = connect(config)
  rescue MirrorError => e
    report.problem("cannot reach #{config[:label]}: #{e.message}.")
    return
  end

  counts = { mirrored: 0, unchanged: paths.length - pending.length, skipped: too_large.length,
             forgotten: 0, failed: 0 }
  work = to_send.map { |n| [:ingest, n] } + gone.map { |k| [:forget, k] }
  work.each_with_index do |(op, item), i|
    if mode == :session_start && elapsed > SESSION_BUDGET
      report.note("sweep stopped at the #{SESSION_BUDGET.to_i}s session-start budget with " \
                  "#{work.length - i} item(s) left; the next session start continues.")
      break
    end

    begin
      if op == :ingest
        mirror_one(client, config, item, state)
        counts[:mirrored] += 1
      else
        forget_one(client, config, item, state)
        counts[:forgotten] += 1
      end
    rescue MirrorError => e
      counts[:failed] += 1
      log("WARN", "#{op} failed for #{op == :ingest ? item[:key] : item}: #{e.message}")
    end
  end

  summary = counts.map { |k, v| "#{k}=#{v}" }.join(" ")
  warn "memory-mirror sweep: #{summary}"
  log("INFO", "sweep #{summary}")
  report.problem("#{counts[:failed]} note(s) failed to reach #{config[:label]} (#{summary}).") if counts[:failed] > 0
  report_oversized(report, config, oversized_keys(state, live))
end

def hook(report)
  payload = begin
    JSON.parse($stdin.read)
  rescue JSON::ParserError
    # The payload quotes the written file; never let it reach the log.
    log("WARN", "hook payload is not JSON")
    return
  end
  raw_path = payload.dig("tool_input", "file_path").to_s
  rel = memory_note(raw_path)
  return if rel.nil?

  path = File.expand_path(raw_path)
  config = load_config
  return if config.nil?

  with_lock do
    state = State.new(create: false)
    key = doc_key(config[:host], rel)

    if File.exist?(path)
      note = prepare_note(config, path, rel, state)
      case note[:status]
      when :unchanged
        nil
      when :too_large
        record_too_large(config, note, state)
        report_oversized(report, config, [note[:key]])
      else
        mirror_one(connect(config), config, note, state)
      end
    elsif state.entries.key?(key)
      forget_one(connect(config), config, key, state)
    end
  end
rescue MirrorError => e
  report.problem("#{rel} was not mirrored: #{e.message}")
end

# --- --check ----------------------------------------------------------------

def jwt_claims(token)
  parts = token.split(".")
  raise MirrorError, "access token is not a JWT (#{parts.length} segments)" unless parts.length == 3

  seg = parts[1].tr("-_", "+/")
  seg += "=" * ((4 - (seg.length % 4)) % 4)
  claims = JSON.parse(seg.unpack1("m").force_encoding(Encoding::UTF_8))
  raise MirrorError, "access token claims are not a JSON object" unless claims.is_a?(Hash)

  claims
rescue JSON::ParserError
  raise MirrorError, "access token claims are not JSON"
end

class CheckRun
  def initialize
    @failed = 0
  end

  def ok?
    @failed == 0
  end

  def pass(msg)
    puts "ok    #{msg}"
  end

  def fail(msg)
    @failed += 1
    puts "FAIL  #{msg}"
  end

  def assert(cond, msg, detail = nil)
    cond ? pass(msg) : fail(detail ? "#{msg} — #{detail}" : msg)
    cond
  end
end

# The call must come back as a policy denial. When it succeeds instead, the
# server policy is not in force: undo whatever the call wrote, then fail. A
# cleanup error propagates rather than being read as a denial.
def expect_denied(run, client, tool, args, what)
  begin
    result = client.call(tool, args)
  rescue ToolCallError => e
    run.assert(e.text.start_with?("policy_denied:"), "#{what} denied with policy_denied:", "got: #{e.text}")
    return
  end
  run.fail("#{what} was NOT denied — the server policy is not in force")
  yield result if block_given?
end

def check
  run = CheckRun.new
  config = load_config
  if config.nil?
    puts "FAIL  no enabled config at #{CONFIG_PATH}"
    return 1
  end
  unless config[:kind] == :client_credentials
    puts "FAIL  --check needs the client_credentials config (#{CONFIG_PATH} uses `server`)"
    return 1
  end

  client_id, secret = read_credentials(config[:credentials_file])
  run.pass("credentials file #{config[:credentials_file]} (0600, both keys)")

  token = fetch_token(config, client_id, secret)
  run.pass("token issued by #{config[:token_url]}")

  claims = jwt_claims(token)
  aud = Array(claims["aud"])
  run.assert(aud.include?(config[:audience]), "token aud includes #{config[:audience].inspect}", "aud=#{aud.inspect}")
  run.assert(claims["sub"] == client_id, "token sub equals the client_id", "sub=#{claims['sub'].inspect}")
  ttl = claims["exp"].is_a?(Integer) && claims["iat"].is_a?(Integer) ? claims["exp"] - claims["iat"] : nil
  run.assert(ttl == EXPECTED_TOKEN_TTL, "token lifetime is #{EXPECTED_TOKEN_TTL}s", "exp-iat=#{ttl.inspect}")

  client = McpClient.new(config[:url], { "authorization" => "Bearer #{token}" })
  client.connect!
  run.pass("MCP session opened at #{config[:url]}")

  dataset = config[:dataset]
  key = "#{config[:host]}/#{SELFTEST_KEY}"
  document = "memory-mirror selftest from #{config[:host]} at #{Time.now.utc.strftime('%FT%TZ')}"
  begin
    first = client.call("ingest", { "document" => document, "dataset" => dataset, "doc_key" => key })
    doc_id = first.is_a?(Hash) ? first["doc_id"].to_s : ""
    run.assert(!doc_id.empty?, "ingest #{dataset}/#{key}", "result=#{short(first.inspect)}")
    unless doc_id.empty?
      by_id = client.call("forget", { "id" => doc_id })
      run.assert(by_id.is_a?(Hash) && by_id["superseded_count"].to_i >= 1, "forget by id",
                 "result=#{short(by_id.inspect)}")
    end

    client.call("ingest", { "document" => document, "dataset" => dataset, "doc_key" => key })
    by_key = client.call("forget", { "dataset" => dataset, "doc_key" => key })
    run.assert(by_key.is_a?(Hash) && by_key["superseded_count"].to_i >= 1, "forget by (dataset, doc_key)",
               "result=#{short(by_key.inspect)}")

    expect_denied(run, client, "recall", { "query" => "memory-mirror selftest", "top_k" => 1 }, "recall")
    denied_key = "#{config[:host]}/_selftest/denied"
    expect_denied(run, client, "ingest",
                  { "document" => document, "dataset" => DENIED_DATASET, "doc_key" => denied_key },
                  "ingest into dataset #{DENIED_DATASET}") do |res|
      leaked = res.is_a?(Hash) ? res["doc_id"].to_s : ""
      client.call("forget", { "id" => leaked }) unless leaked.empty?
      client.call("forget", { "dataset" => DENIED_DATASET, "doc_key" => denied_key })
      puts "      cleaned up the unexpected write to #{DENIED_DATASET}/#{denied_key}"
    end
    expect_denied(run, client, "forget", { "dataset" => DENIED_DATASET, "doc_key" => denied_key },
                  "forget in dataset #{DENIED_DATASET}")
  ensure
    begin
      client.call("forget", { "dataset" => dataset, "doc_key" => key })
    rescue MirrorError => e
      run.fail("selftest cleanup of #{dataset}/#{key}: #{e.message}")
    end
  end

  run.ok? ? 0 : 1
rescue MirrorError => e
  puts "FAIL  #{e.message}"
  1
rescue StandardError => e
  puts "FAIL  internal error #{e.class} at #{short(e.backtrace&.first)}"
  1
end

# --- entry point ------------------------------------------------------------

def run_sweep(mode, report)
  config = load_config
  if config.nil?
    log("INFO", "sweep skipped: no enabled config at #{CONFIG_PATH}")
    return
  end

  with_lock { sweep(config, mode, report) }
end

# Returns the exit status: hook modes always 0; --check and a manual --sweep
# report failure through it.
def main
  return check if ARGV.include?("--check")

  if ARGV.include?("--sweep")
    mode =
      if ARGV.include?("--dry-run") then :dry_run
      elsif ARGV.include?("--session-start") then :session_start
      else :manual
      end
    report = Report.new(mode == :session_start ? "SessionStart" : nil)
  else
    mode = :hook
    report = Report.new("PostToolUse")
  end

  begin
    mode == :hook ? hook(report) : run_sweep(mode, report)
  rescue MirrorError => e
    report.problem(e.message)
  rescue StandardError => e
    # Unexpected: the message may quote file content, so only class + location.
    report.problem("internal error #{e.class} at #{short(e.backtrace&.first)}")
  ensure
    report.emit
  end

  mode == :manual && !report.problems.empty? ? 1 : 0
end

status =
  begin
    main
  rescue StandardError => e
    log("WARN", "#{e.class} at #{short(e.backtrace&.first)}")
    ARGV.include?("--check") ? 1 : 0
  end

exit status
