require 'sinatra'
require 'net/http'
require 'uri'
require 'json'
require 'securerandom'
require 'dotenv/load'

SESSIONS = {}

get '/' do
  "✅ SketchShaper Patreon Auth Server Running"
end

get '/login' do
  state = SecureRandom.hex(10)
  SESSIONS[state] = { status: 'pending' }

  redirect_url = "https://www.patreon.com/oauth2/authorize?response_type=code" \
                 "&client_id=#{ENV['CLIENT_ID']}" \
                 "&redirect_uri=#{ENV['REDIRECT_URI']}" \
                 "&state=#{state}" \
                 "&scope=identity"

  redirect redirect_url
end

get '/callback' do
  code = params[:code]
  state = params[:state]

  uri = URI("https://www.patreon.com/api/oauth2/token")
  response = Net::HTTP.post_form(uri, {
    "code" => code,
    "grant_type" => "authorization_code",
    "client_id" => ENV['CLIENT_ID'],
    "client_secret" => ENV['CLIENT_SECRET'],
    "redirect_uri" => ENV['REDIRECT_URI']
  })

  token_data = JSON.parse(response.body)
  access_token = token_data["access_token"]

  # Fetch user info
  uri = URI("https://www.patreon.com/api/oauth2/v2/identity")
  req = Net::HTTP::Get.new(uri)
  req['Authorization'] = "Bearer #{access_token}"
  res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }

  user_info = JSON.parse(res.body)

  # Save user info in session
  SESSIONS[state][:status] = "success"
  SESSIONS[state][:user] = user_info

  "✅ Login successful! You can return to SketchUp now."
end

get '/status/:state' do
  content_type :json
  session = SESSIONS[params[:state]]
  if session
    session.to_json
  else
    { status: "unknown" }.to_json
  end
end
