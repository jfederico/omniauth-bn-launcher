require 'omniauth'
require 'digest'
require 'omniauth-oauth2'
module OmniAuth
  module Strategies
    class BnLauncher < OmniAuth::Strategies::OAuth2

      option :name, 'bn_launcher'
      option :customer, nil

      def request_phase
        options.authorize_params[:customer] = options[:customer]
        super
      end

      def callback_phase
        puts "BN LAUNCHER DEBUG:  ", !options.provider_ignores_state, request.params["state"].to_s.empty?, request.params["state"], session["omniauth.state"]
        puts request.query_string
        if request.host == "demo.gl.greenlight.com"
          response = Rack::Response.new
          response.redirect "http://ice.gl.greenlight.com:4000/auth/bn_launcher/callback?#{request.query_string}"
          response.finish
          return
        end
        super
      end

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid{ raw_info['uid'] }

      info do
        {
            :name => raw_info['name'],
            :email => raw_info['email'],
            :image => raw_info['image'],
            :username => raw_info['username']
        }
      end

      extra do
        {
            'raw_info' => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get("/user").parsed
      end
    end
  end
end