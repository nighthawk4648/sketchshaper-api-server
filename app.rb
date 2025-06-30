require 'sinatra'
require 'net/http'
require 'uri'
require 'json'
require 'securerandom'
require 'dotenv/load'
require 'logger'
require 'time'

logger = Logger.new(STDOUT)
logger.level = Logger::DEBUG

SESSIONS = {}
ALLOWED_TIER = ENV['ALLOWED_TIER'] || "Sketch shaper-Pro"

# Generic error handler
error do
  logger.error "Error: #{env['sinatra.error']}"
  logger.error env['sinatra.error'].backtrace.join("\n")
  "Internal Server Error: #{env['sinatra.error'].message}"
end

get '/' do
  logger.info "Root accessed"
  "✅ SketchShaper Patreon Auth Server Running"
end

get '/login' do
  logger.info "Login endpoint hit"

  unless ENV['CLIENT_ID'] && ENV['REDIRECT_URI']
    logger.error "Missing env vars"
    halt 500, "Missing CLIENT_ID or REDIRECT_URI"
  end

  client_state = params[:client_state]
  state = client_state || SecureRandom.hex(10)

  SESSIONS[state] = {
    status: 'pending',
    created_at: Time.now,
    client_state: !client_state.nil?
  }

  redirect_url = "https://www.patreon.com/oauth2/authorize?" +
                 "response_type=code" \
                 "&client_id=#{ENV['CLIENT_ID']}" \
                 "&redirect_uri=#{URI.encode_www_form_component(ENV['REDIRECT_URI'])}" \
                 "&state=#{state}" \
                 "&scope=identity%20identity.memberships"

  redirect redirect_url
end

get '/status/:state' do
  content_type :json
  session = SESSIONS[params[:state]]
  if session
    session.to_json
  else
    {
      status: "unknown",
      suggestion: "Ensure you completed the browser flow",
      server_time: Time.now.iso8601
    }.to_json
  end
end

get '/callback' do
  code = params[:code]
  state = params[:state]
  error_param = params[:error]

  if error_param
    halt 400, "OAuth Error: #{error_param} - #{params[:error_description]}"
  end

  halt 400, "Missing required parameters" unless code && state
  halt 400, "Invalid state" unless SESSIONS[state]

  unless ENV['CLIENT_ID'] && ENV['CLIENT_SECRET'] && ENV['REDIRECT_URI']
    halt 500, "Missing required env vars"
  end

  begin
    uri = URI("https://www.patreon.com/api/oauth2/token")
    response = Net::HTTP.post_form(uri, {
      "code" => code,
      "grant_type" => "authorization_code",
      "client_id" => ENV['CLIENT_ID'],
      "client_secret" => ENV['CLIENT_SECRET'],
      "redirect_uri" => ENV['REDIRECT_URI']
    })

    halt 500, "Token exchange failed" unless response.code == '200'
    token_data = JSON.parse(response.body)
    access_token = token_data["access_token"]

    halt 500, "No access token received" unless access_token

    uri = URI("https://www.patreon.com/api/oauth2/v2/identity" \
              "?include=memberships.currently_entitled_tiers" \
              "&fields[member]=patron_status,currently_entitled_tiers" \
              "&fields[tier]=title")

    req = Net::HTTP::Get.new(uri)
    req['Authorization'] = "Bearer #{access_token}"

    res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
      http.request(req)
    end

    halt 500, "User info fetch failed" unless res.code == '200'

    user_info = JSON.parse(res.body)
    memberships = user_info["included"] || []

    entitled_tiers = memberships.select { |m| m["type"] == "tier" }
    tier_titles = entitled_tiers.map { |t| t.dig("attributes", "title") }.compact

    logger.info "User's entitled tiers: #{tier_titles.inspect}"

    unless tier_titles.include?(ALLOWED_TIER)
      return erb :unauthorized, locals: { tier_titles: tier_titles, allowed_tier: ALLOWED_TIER }
    end

    SESSIONS[state][:status] = "success"
    SESSIONS[state][:user] = user_info
    "✅ Login successful! You can return to SketchUp now."

  rescue => e
    logger.error "Callback error: #{e.message}"
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

# Simple view for unauthorized users
__END__

@@ unauthorized
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Access Denied</title>
  <style>
    body {
      background: #fdfdfd;
      color: #333;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      text-align: center;
      padding-top: 100px;
    }
    .container {
      background: #fff;
      margin: auto;
      padding: 40px;
      max-width: 500px;
      box-shadow: 0 4px 10px rgba(0,0,0,0.1);
      border-radius: 12px;
    }
    h1 {
      color: #d9534f;
    }
    p {
      margin-top: 20px;
      font-size: 18px;
    }
    a {
      display: inline-block;
      margin-top: 30px;
      text-decoration: none;
      color: white;
      background-color: #007bff;
      padding: 10px 20px;
      border-radius: 6px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚫 Access Denied</h1>
    <p>You must be a <strong><%= allowed_tier %></strong> member to access this feature.</p>
    <p>Your current tier(s): <%= tier_titles.empty? ? "None" : tier_titles.join(", ") %></p>
    <a href="https://www.patreon.com/sketchshaper" target="_blank">Become a Member</a>
  </div>
</body>
</html>
