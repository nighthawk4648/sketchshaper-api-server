# config.ru
require 'dotenv/load'  # Optional: loads environment variables
require './app'        # assumes your main app file is app.rb

run Sinatra::Application
