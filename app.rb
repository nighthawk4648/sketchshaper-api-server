require 'sinatra'
require 'net/http'
require 'uri'
require 'json'
require 'securerandom'
require 'dotenv/load'
require 'logger'
require 'time'

# Set up logging
logger = Logger.new(STDOUT)
logger.level = Logger::DEBUG

SESSIONS = {}

ALLOWED_TIER = ENV['ALLOWED_TIER'] || "Pro Access"

# Error handling
error do
  logger.error "Error occurred: #{env['sinatra.error']}"
  logger.error env['sinatra.error'].backtrace.join("\n")
  "Internal Server Error: #{env['sinatra.error'].message}"
end

get '/' do
  logger.info "Root endpoint accessed"
  "✅ SketchShaper Patreon Auth Server Running"
end

get '/login' do
  logger.info "Login endpoint accessed"
  
  unless ENV['CLIENT_ID'] && ENV['REDIRECT_URI']
    logger.error "Missing environment variables"
    halt 500, "Missing CLIENT_ID or REDIRECT_URI environment variables"
  end
  
  client_state = params[:client_state]
  state = client_state || SecureRandom.hex(10)

  SESSIONS[state] = {
    status: 'pending',
    created_at: Time.now,
    client_state: client_state ? true : false
  }
  logger.info "Created session with state: #{state}"

  redirect_url = "https://www.patreon.com/oauth2/authorize?response_type=code" \
               "&client_id=#{ENV['CLIENT_ID']}" \
               "&redirect_uri=#{URI.encode_www_form_component(ENV['REDIRECT_URI'])}" \
               "&state=#{state}" \
               "&scope=identity%20identity.memberships"

  logger.info "Redirecting to: #{redirect_url}"
  redirect redirect_url
end

get '/status/:state' do
  logger.info "Status check for state: #{params[:state]}"
  content_type :json

  session = SESSIONS[params[:state]]
  if session
    logger.info "Session found: #{session[:status]}"
    session.to_json
  else
    logger.info "Session not found"
    {
      status: "unknown",
      suggestion: "Ensure you completed the browser flow",
      server_time: Time.now.iso8601
    }.to_json
  end
end

get '/callback' do
  logger.info "Callback endpoint accessed with params: #{params.inspect}"

  code = params[:code]
  state = params[:state]
  error_param = params[:error]

  if error_param
    logger.error "OAuth error: #{error_param} - #{params[:error_description]}"
    halt 400, "OAuth Error: #{error_param} - #{params[:error_description]}"
  end

  unless code && state
    logger.error "Missing required parameters: code=#{code}, state=#{state}"
    halt 400, "Missing required parameters (code or state)"
  end

  unless SESSIONS[state]
    logger.error "Invalid state parameter: #{state}"
    halt 400, "Invalid state parameter"
  end

  unless ENV['CLIENT_ID'] && ENV['CLIENT_SECRET'] && ENV['REDIRECT_URI']
    logger.error "Missing environment variables for token exchange"
    halt 500, "Missing required environment variables"
  end

  begin
    logger.info "Exchanging code for token..."
    uri = URI("https://www.patreon.com/api/oauth2/token")
    response = Net::HTTP.post_form(uri, {
      "code" => code,
      "grant_type" => "authorization_code",
      "client_id" => ENV['CLIENT_ID'],
      "client_secret" => ENV['CLIENT_SECRET'],
      "redirect_uri" => ENV['REDIRECT_URI']
    })

    logger.info "Token response status: #{response.code}"
    logger.info "Token response body: #{response.body}"

    unless response.code == '200'
      logger.error "Token exchange failed: #{response.code} - #{response.body}"
      halt 500, "Token exchange failed: #{response.body}"
    end

    token_data = JSON.parse(response.body)
    access_token = token_data["access_token"]
    unless access_token
      logger.error "No access token in response: #{token_data}"
      halt 500, "No access token received"
    end

    # Fetch user info with membership data
    logger.info "Fetching user info with memberships..."
    uri = URI("https://www.patreon.com/api/oauth2/v2/identity" \
              "?include=memberships.currently_entitled_tiers" \
              "&fields[member]=patron_status,currently_entitled_tiers" \
              "&fields[tier]=title")
    req = Net::HTTP::Get.new(uri)
    req['Authorization'] = "Bearer #{access_token}"

    res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
      http.request(req)
    end

    logger.info "User info response status: #{res.code}"
    logger.info "User info response body: #{res.body}"

    unless res.code == '200'
      logger.error "User info fetch failed: #{res.code} - #{res.body}"
      halt 500, "User info fetch failed: #{res.body}"
    end

    user_info = JSON.parse(res.body)
    memberships = user_info.dig("included")

    entitled_tiers = memberships&.map do |m|
      m.dig("relationships", "currently_entitled_tiers", "data")
    end&.flatten

    tier_titles = entitled_tiers&.map do |tier_ref|
      memberships.find { |i| i["id"] == tier_ref["id"] && i["type"] == "tier" }
    end&.map { |t| t&.dig("attributes", "title") }&.compact

    logger.info "User entitled tiers: #{tier_titles.inspect}"

    unless tier_titles.include?(ALLOWED_TIER)
      logger.warn "User is not in allowed tier: #{tier_titles.inspect}"
      halt 403, "Access denied: You must be a member of the '#{ALLOWED_TIER}' tier."
    end

    SESSIONS[state][:status] = "success"
    SESSIONS[state][:user] = user_info

    logger.info "Login successful for state: #{state}"
    "✅ Login successful! You can return to SketchUp now."

  rescue JSON::ParserError => e
    logger.error "JSON parsing error: #{e.message}"
    halt 500, "JSON parsing error: #{e.message}"
  rescue Net::HTTPError => e
    logger.error "HTTP error: #{e.message}"
    halt 500, "HTTP error: #{e.message}"
  rescue => e
    logger.error "Unexpected error: #{e.message}"
    logger.error e.backtrace.join("\n")
    halt 500, "Unexpected error: #{e.message}"
  end
end

# Health check
get '/health' do
  content_type :json
  {
    status: "ok",
    timestamp: Time.now.iso8601,
    sessions_count: SESSIONS.length,
    env_vars: {
      client_id: ENV['CLIENT_ID'] ? "set" : "missing",
      client_secret: ENV['CLIENT_SECRET'] ? "set" : "missing",
      redirect_uri: ENV['REDIRECT_URI'] ? "set" : "missing",
      allowed_tier: ALLOWED_TIER
    }
  }.to_json
end
