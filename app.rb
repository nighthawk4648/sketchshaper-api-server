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
# Parse multiple allowed tiers from environment variable
ALLOWED_TIERS = (ENV['ALLOWED_TIERS'] || ENV['ALLOWED_TIER'] || "Free").split(',').map(&:strip)

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

  logger.info "Callback received - State: #{state}, Code present: #{!code.nil?}"

  if error_param
    logger.error "OAuth Error: #{error_param} - #{params[:error_description]}"
    halt 400, "OAuth Error: #{error_param} - #{params[:error_description]}"
  end

  halt 400, "Missing required parameters" unless code && state
  halt 400, "Invalid state" unless SESSIONS[state]

  unless ENV['CLIENT_ID'] && ENV['CLIENT_SECRET'] && ENV['REDIRECT_URI']
    logger.error "Missing required environment variables"
    halt 500, "Missing required env vars"
  end

  begin
    # Step 1: Exchange code for access token
    logger.info "Exchanging authorization code for access token"
    uri = URI("https://www.patreon.com/api/oauth2/token")
    
    token_request = Net::HTTP::Post.new(uri)
    token_request.set_form_data({
      "code" => code,
      "grant_type" => "authorization_code",
      "client_id" => ENV['CLIENT_ID'],
      "client_secret" => ENV['CLIENT_SECRET'],
      "redirect_uri" => ENV['REDIRECT_URI']
    })

    token_response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
      http.request(token_request)
    end

    logger.info "Token exchange response code: #{token_response.code}"
    
    if token_response.code != '200'
      logger.error "Token exchange failed with code: #{token_response.code}"
      logger.error "Token exchange response body: #{token_response.body}"
      halt 500, "Token exchange failed: #{token_response.code} - #{token_response.body}"
    end

    token_data = JSON.parse(token_response.body)
    access_token = token_data["access_token"]

    if access_token.nil? || access_token.empty?
      logger.error "No access token in response: #{token_data}"
      halt 500, "No access token received"
    end

    logger.info "Access token received successfully (length: #{access_token.length})"

    # Step 2: Get user identity and memberships with better error handling
    logger.info "Fetching user identity and memberships"
    
    # Updated API endpoint with correct fields
    identity_uri = URI("https://www.patreon.com/api/oauth2/v2/identity?" +
                      "include=memberships,memberships.currently_entitled_tiers" +
                      "&fields[user]=email,first_name,full_name" +
                      "&fields[member]=patron_status,currently_entitled_amount_cents" +
                      "&fields[tier]=title,amount_cents")

    identity_req = Net::HTTP::Get.new(identity_uri)
    identity_req['Authorization'] = "Bearer #{access_token}"
    identity_req['User-Agent'] = 'SketchShaper/1.0'
    identity_req['Accept'] = 'application/json'

    logger.info "Making request to: #{identity_uri}"
    logger.info "Authorization header: Bearer #{access_token[0..10]}..."

    identity_response = Net::HTTP.start(identity_uri.hostname, identity_uri.port, use_ssl: true) do |http|
      http.read_timeout = 30
      http.open_timeout = 10
      http.request(identity_req)
    end

    logger.info "Identity API response code: #{identity_response.code}"
    logger.info "Identity API response headers: #{identity_response.to_hash}"
    
    if identity_response.code != '200'
      logger.error "Identity API failed with code: #{identity_response.code}"
      logger.error "Identity API response body: #{identity_response.body}"
      
      # Handle specific HTTP error codes
      case identity_response.code
      when '401'
        halt 500, "Authentication failed - Invalid access token"
      when '403'
        halt 500, "Access forbidden - Check API permissions and scopes"
      when '429'
        halt 500, "Rate limit exceeded - Please try again later"
      when '500', '502', '503'
        halt 500, "Patreon API is temporarily unavailable - Please try again later"
      else
        halt 500, "User info fetch failed: #{identity_response.code} - #{identity_response.body}"
      end
    end

    user_info = JSON.parse(identity_response.body)
    logger.info "User info received successfully"
    logger.debug "User info structure: #{user_info.keys}"

    # Step 3: Process membership data with better error handling
    included_data = user_info["included"] || []
    logger.info "Included data count: #{included_data.length}"

    # Find memberships and tiers
    memberships = included_data.select { |item| item["type"] == "member" }
    tiers = included_data.select { |item| item["type"] == "tier" }
    
    logger.info "Found #{memberships.length} memberships and #{tiers.length} tiers"

    # Get entitled tier titles
    entitled_tier_ids = []
    memberships.each do |membership|
      relationships = membership.dig("relationships", "currently_entitled_tiers", "data") || []
      entitled_tier_ids.concat(relationships.map { |rel| rel["id"] })
    end

    tier_titles = tiers.select { |tier| entitled_tier_ids.include?(tier["id"]) }
                      .map { |tier| tier.dig("attributes", "title") }
                      .compact

    logger.info "User's entitled tiers: #{tier_titles.inspect}"
    logger.info "Required tiers: #{ALLOWED_TIERS.inspect}"

    # Check if user has any of the required tiers
    has_access = tier_titles.any? { |user_tier| ALLOWED_TIERS.include?(user_tier) }
    
    unless has_access
      logger.info "User does not have any required tier - showing unauthorized page"
      SESSIONS[state][:status] = "unauthorized"
      SESSIONS[state][:tier_titles] = tier_titles
      return erb :unauthorized, locals: { 
        tier_titles: tier_titles, 
        allowed_tiers: ALLOWED_TIERS 
      }
    end

    # Success case
    logger.info "User authorized successfully"
    SESSIONS[state][:status] = "success"
    SESSIONS[state][:user] = user_info
    SESSIONS[state][:tier_titles] = tier_titles
    
    # Get user's name for personalization
    user_name = user_info.dig("data", "attributes", "full_name") || 
                user_info.dig("data", "attributes", "first_name") || 
                "Patron"
    
    erb :success, locals: { 
      user_name: user_name,
      tier_titles: tier_titles,
      allowed_tiers: ALLOWED_TIERS
    }

  rescue JSON::ParserError => e
    logger.error "JSON parsing error: #{e.message}"
    halt 500, "Invalid JSON response from Patreon API"
  rescue Net::TimeoutError => e
    logger.error "Timeout error: #{e.message}"
    halt 500, "Request timeout - Patreon API is not responding"
  rescue Net::OpenTimeout => e
    logger.error "Connection timeout: #{e.message}"
    halt 500, "Connection timeout - Unable to reach Patreon API"
  rescue StandardError => e
    logger.error "Unexpected error in callback: #{e.message}"
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
      allowed_tiers: ALLOWED_TIERS
    }
  }.to_json
end

# Cleanup old sessions (optional - run periodically)
get '/cleanup' do
  content_type :json
  old_sessions = SESSIONS.select { |_, session| 
    Time.now - session[:created_at] > 3600 # 1 hour old
  }
  
  old_sessions.each { |state, _| SESSIONS.delete(state) }
  
  {
    status: "cleanup_complete",
    removed_sessions: old_sessions.length,
    remaining_sessions: SESSIONS.length
  }.to_json
end

# Simple view for unauthorized users
__END__

@@ success
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Login Successful</title>
  <style>
    body {
      background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      text-align: center;
      padding-top: 50px;
      min-height: 100vh;
      margin: 0;
    }
    .container {
      background: #fff;
      margin: auto;
      padding: 50px 40px;
      max-width: 500px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.2);
      border-radius: 20px;
      position: relative;
      overflow: hidden;
    }
    .container::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 5px;
      background: linear-gradient(90deg, #4CAF50, #45a049);
    }
    .success-icon {
      font-size: 4rem;
      color: #4CAF50;
      margin-bottom: 20px;
      animation: bounce 1s ease-in-out;
    }
    @keyframes bounce {
      0%, 20%, 60%, 100% { transform: translateY(0); }
      40% { transform: translateY(-20px); }
      80% { transform: translateY(-10px); }
    }
    h1 {
      color: #4CAF50;
      margin-bottom: 10px;
      font-size: 2.2rem;
      font-weight: 300;
    }
    .welcome-text {
      font-size: 1.2rem;
      color: #666;
      margin-bottom: 30px;
    }
    .tier-info {
      background: #f8f9fa;
      padding: 20px;
      border-radius: 10px;
      margin: 20px 0;
      border-left: 4px solid #4CAF50;
    }
    .tier-info h3 {
      margin: 0 0 10px 0;
      color: #333;
      font-size: 1.1rem;
    }
    .tier-badge {
      display: inline-block;
      background: #4CAF50;
      color: white;
      padding: 8px 16px;
      border-radius: 20px;
      font-weight: bold;
      margin: 5px;
      font-size: 0.9rem;
    }
    .instructions {
      background: #e8f4fd;
      padding: 20px;
      border-radius: 10px;
      margin: 30px 0;
      border-left: 4px solid #2196F3;
    }
    .instructions h3 {
      margin: 0 0 10px 0;
      color: #1976D2;
      font-size: 1.1rem;
    }
    .instructions p {
      margin: 10px 0;
      color: #555;
      line-height: 1.5;
    }
    .close-btn {
      display: inline-block;
      margin-top: 30px;
      text-decoration: none;
      color: white;
      background: linear-gradient(45deg, #667eea, #764ba2);
      padding: 12px 30px;
      border-radius: 25px;
      font-weight: bold;
      transition: all 0.3s ease;
      box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
    }
    .close-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
    }
    .footer {
      margin-top: 30px;
      font-size: 0.9rem;
      color: #888;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="success-icon">✅</div>
    <h1>Welcome Back!</h1>
    <p class="welcome-text">Hello <%= user_name %>, you're successfully authenticated!</p>
    
    <div class="tier-info">
      <h3>🎖️ Your Membership Status</h3>
      <% tier_titles.each do |tier| %>
        <span class="tier-badge"><%= tier %></span>
      <% end %>
    </div>
    
    <div class="instructions">
      <h3>📋 Next Steps</h3>
      <p><strong>1.</strong> You can now close this browser tab</p>
      <p><strong>2.</strong> Return to SketchUp to continue using SketchShaper</p>
      <p><strong>3.</strong> Your authentication will remain active for this session</p>
    </div>
    
    <a href="#" class="close-btn" onclick="window.close(); return false;">Close & Return to SketchUp</a>
    
    <div class="footer">
      Thank you for supporting SketchShaper! 🙏
    </div>
  </div>

  <script>
    // Auto-close after 5 seconds if user doesn't click
    setTimeout(function() {
      if (confirm('Authentication successful! Close this window and return to SketchUp?')) {
        window.close();
      }
    }, 5000);
  </script>
</body>
</html>

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
    .allowed-tiers {
      font-weight: bold;
      color: #007bff;
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
    <p>You must be a member of one of these tiers to access this feature:</p>
    <p class="allowed-tiers"><%= allowed_tiers.join(", ") %></p>
    <p>Your current tier(s): <%= tier_titles.empty? ? "None" : tier_titles.join(", ") %></p>

    <a href="https://www.patreon.com/sketchshaper/membership" target="_blank">Become a Member</a>
  </div>
</body>
</html>

