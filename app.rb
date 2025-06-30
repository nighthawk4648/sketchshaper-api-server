require 'sinatra'
require 'net/http'
require 'uri'
require 'json'
require 'securerandom'
require 'dotenv/load'
require 'logger'

# Set up logging
logger = Logger.new(STDOUT)
logger.level = Logger::DEBUG

# RENDER FIX: Use in-memory session store instead of file system
# This works around Render's read-only filesystem limitations
class SessionStore
  def initialize
    @sessions = {}
    @cleanup_interval = 3600 # 1 hour
    @last_cleanup = Time.now
    logger.info "🚀 In-memory session store initialized"
  end

  def save(state, data)
    cleanup_expired_sessions
    @sessions[state] = {
      data: data,
      created_at: Time.now,
      expires_at: Time.now + @cleanup_interval
    }
    logger.info "💾 Session saved in memory: #{state}"
    logger.info "📊 Total active sessions: #{@sessions.size}"
    true
  rescue => e
    logger.error "❌ Failed to save session: #{e.message}"
    false
  end

  def load(state)
    cleanup_expired_sessions
    session = @sessions[state]
    if session && session[:expires_at] > Time.now
      logger.info "📖 Session loaded from memory: #{state}"
      session[:data]
    else
      logger.error "❌ Session not found or expired: #{state}"
      logger.info "🔍 Available sessions: #{@sessions.keys}"
      nil
    end
  rescue => e
    logger.error "❌ Failed to load session: #{e.message}"
    nil
  end

  def delete(state)
    @sessions.delete(state)
    logger.info "🗑️ Session deleted: #{state}"
  end

  def stats
    cleanup_expired_sessions
    {
      total_sessions: @sessions.size,
      active_sessions: @sessions.keys,
      last_cleanup: @last_cleanup,
      next_cleanup: @last_cleanup + @cleanup_interval
    }
  end

  private

  def cleanup_expired_sessions
    return unless Time.now - @last_cleanup > 300 # Cleanup every 5 minutes

    before_count = @sessions.size
    @sessions.reject! { |_, session| session[:expires_at] <= Time.now }
    after_count = @sessions.size

    if before_count != after_count
      logger.info "🧹 Cleaned up #{before_count - after_count} expired sessions"
    end

    @last_cleanup = Time.now
  end
end

# Initialize the session store
SESSION_STORE = SessionStore.new

# Error handling
error do
  logger.error "Error occurred: #{env['sinatra.error']}"
  logger.error env['sinatra.error'].backtrace.join("\n")
  "Internal Server Error: #{env['sinatra.error'].message}"
end

# Health check
get '/' do
  logger.info "Root endpoint accessed"
  "✅ SketchShaper Patreon Auth Server Running on Render"
end

get '/login' do
  logger.info "Login endpoint accessed"

  unless ENV['CLIENT_ID'] && ENV['REDIRECT_URI']
    logger.error "Missing environment variables"
    logger.error "CLIENT_ID: #{ENV['CLIENT_ID'] ? 'set' : 'MISSING'}"
    logger.error "REDIRECT_URI: #{ENV['REDIRECT_URI'] ? 'set' : 'MISSING'}"
    halt 500, "Missing CLIENT_ID or REDIRECT_URI environment variables"
  end

  state = SecureRandom.hex(16)
  session_data = {
    status: 'pending',
    created: Time.now.to_i,
    client_id: ENV['CLIENT_ID'],
    redirect_uri: ENV['REDIRECT_URI']
  }

  unless SESSION_STORE.save(state, session_data)
    halt 500, "Failed to create session"
  end

  # Use CGI.escape for better URL encoding on Render
  redirect_url = "https://www.patreon.com/oauth2/authorize?" +
                 "response_type=code&" +
                 "client_id=#{ENV['CLIENT_ID']}&" +
                 "redirect_uri=#{CGI.escape(ENV['REDIRECT_URI'])}&" +
                 "state=#{state}&" +
                 "scope=identity"

  logger.info "🔐 State generated: #{state}"
  logger.info "🔗 Redirect URI: #{ENV['REDIRECT_URI']}"
  logger.info "➡️ Redirecting to Patreon..."
  
  redirect redirect_url
end

get '/callback' do
  logger.info "=== CALLBACK RECEIVED ==="
  logger.info "🌐 Request URL: #{request.url}"
  logger.info "❓ Query string: #{request.query_string}"
  logger.info "📋 All params: #{params.inspect}"
  logger.info "📊 Session stats: #{SESSION_STORE.stats}"
  logger.info "========================"

  code = params[:code]
  state = params[:state]
  error_param = params[:error]

  # Handle OAuth errors
  if error_param
    logger.error "❌ OAuth error: #{error_param}"
    logger.error "📝 Error description: #{params[:error_description]}"
    return "❌ OAuth Error: #{error_param} - #{params[:error_description] || 'No description provided'}"
  end

  # Check required parameters
  unless code && state
    logger.error "❌ Missing required parameters"
    logger.error "  Code: #{code ? 'present' : 'MISSING'}"
    logger.error "  State: #{state ? 'present' : 'MISSING'}"

    debug_info = {
      error: "Missing required parameters (code or state)",
      received_params: params,
      query_string: request.query_string,
      full_url: request.url,
      method: request.request_method,
      session_stats: SESSION_STORE.stats,
      environment: {
        client_id: ENV['CLIENT_ID'] ? "set" : "missing",
        redirect_uri: ENV['REDIRECT_URI'] ? "set" : "missing"
      }
    }

    content_type :json
    return JSON.pretty_generate(debug_info)
  end

  # Load session
  session_data = SESSION_STORE.load(state)
  unless session_data
    logger.error "❌ Invalid or expired state: #{state}"
    logger.error "🔍 Available sessions: #{SESSION_STORE.stats[:active_sessions]}"
    
    error_response = {
      error: "Invalid state parameter",
      state: state,
      session_stats: SESSION_STORE.stats
    }
    
    content_type :json
    halt 400, JSON.pretty_generate(error_response)
  end

  logger.info "✅ Found valid session for state: #{state}"

  # Verify environment variables
  unless ENV['CLIENT_ID'] && ENV['CLIENT_SECRET'] && ENV['REDIRECT_URI']
    logger.error "❌ Missing environment variables for token exchange"
    halt 500, "Missing required environment variables"
  end

  begin
    logger.info "🔄 Exchanging authorization code for access token..."
    
    # Token exchange
    uri = URI("https://www.patreon.com/api/oauth2/token")
    
    # Use proper Net::HTTP with timeout for Render
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.read_timeout = 30
    http.open_timeout = 10

    request = Net::HTTP::Post.new(uri)
    request.set_form_data({
      "code" => code,
      "grant_type" => "authorization_code",
      "client_id" => ENV['CLIENT_ID'],
      "client_secret" => ENV['CLIENT_SECRET'],
      "redirect_uri" => ENV['REDIRECT_URI']
    })

    response = http.request(request)

    logger.info "📡 Token response status: #{response.code}"
    logger.info "📄 Token response body: #{response.body[0..200]}#{response.body.length > 200 ? '...' : ''}"

    unless response.code == '200'
      logger.error "❌ Token exchange failed: #{response.code}"
      halt 500, "Token exchange failed: #{response.body}"
    end

    token_data = JSON.parse(response.body)
    access_token = token_data["access_token"]

    unless access_token
      logger.error "❌ No access token in response"
      halt 500, "No access token received"
    end

    logger.info "✅ Access token received"
    logger.info "👤 Fetching user information..."

    # Fetch user info
    user_uri = URI("https://www.patreon.com/api/oauth2/v2/identity")
    user_http = Net::HTTP.new(user_uri.host, user_uri.port)
    user_http.use_ssl = true
    user_http.read_timeout = 30

    user_req = Net::HTTP::Get.new(user_uri)
    user_req['Authorization'] = "Bearer #{access_token}"

    user_res = user_http.request(user_req)

    logger.info "👤 User info response status: #{user_res.code}"
    logger.info "👤 User info response: #{user_res.body[0..200]}#{user_res.body.length > 200 ? '...' : ''}"

    unless user_res.code == '200'
      logger.error "❌ User info fetch failed"
      halt 500, "User info fetch failed: #{user_res.body}"
    end

    user_info = JSON.parse(user_res.body)

    # Update session with success
    success_data = {
      status: 'success',
      user: user_info,
      completed_at: Time.now.to_i,
      access_token: access_token # Store for potential future use
    }
    SESSION_STORE.save(state, success_data)

    logger.info "🎉 Login successful for state: #{state}"
    logger.info "👤 User ID: #{user_info.dig('data', 'id')}"

    "✅ Login successful! You can return to SketchUp now."

  rescue JSON::ParserError => e
    logger.error "❌ JSON parsing error: #{e.message}"
    halt 500, "JSON parsing error: #{e.message}"
  rescue Net::TimeoutError => e
    logger.error "❌ Network timeout: #{e.message}"
    halt 500, "Network timeout - please try again"
  rescue => e
    logger.error "❌ Unexpected error: #{e.message}"
    logger.error e.backtrace[0..5].join("\n")
    halt 500, "Unexpected error: #{e.message}"
  end
end

get '/status/:state' do
  logger.info "📊 Status check for state: #{params[:state]}"
  content_type :json

  session_data = SESSION_STORE.load(params[:state])
  if session_data
    # Don't expose sensitive data
    safe_data = session_data.dup
    safe_data.delete('access_token') if safe_data['access_token']
    safe_data.to_json
  else
    { status: "unknown", error: "Session not found or expired" }.to_json
  end
end

get '/health' do
  content_type :json
  {
    status: "ok",
    platform: "render",
    timestamp: Time.now.iso8601,
    session_store: "in-memory",
    session_stats: SESSION_STORE.stats,
    environment: {
      client_id: ENV['CLIENT_ID'] ? "set (#{ENV['CLIENT_ID'].length} chars)" : "missing",
      client_secret: ENV['CLIENT_SECRET'] ? "set (#{ENV['CLIENT_SECRET'].length} chars)" : "missing",
      redirect_uri: ENV['REDIRECT_URI'] || "missing"
    },
    ruby_version: RUBY_VERSION,
    sinatra_version: Sinatra::VERSION
  }.to_json
end

# Debug endpoint for Render troubleshooting
get '/debug' do
  content_type :json
  {
    platform: "render",
    session_store_type: "in-memory",
    session_stats: SESSION_STORE.stats,
    environment_variables: ENV.to_h.select { |k, v| 
      k.include?('CLIENT') || k.include?('REDIRECT') || k.include?('PORT') || k.include?('RENDER')
    }.transform_values { |v| v ? "set (#{v.to_s.length} chars)" : "missing" },
    request_info: {
      host: request.host,
      port: request.port,
      scheme: request.scheme,
      base_url: "#{request.scheme}://#{request.host_with_port}"
    }
  }.to_json
end

# Cleanup endpoint (useful for long-running Render services)
get '/cleanup' do
  content_type :json
  before_stats = SESSION_STORE.stats
  SESSION_STORE.send(:cleanup_expired_sessions)
  after_stats = SESSION_STORE.stats
  
  {
    message: "Cleanup completed",
    before: before_stats,
    after: after_stats
  }.to_json
end
