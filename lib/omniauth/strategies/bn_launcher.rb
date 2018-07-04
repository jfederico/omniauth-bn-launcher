require 'omniauth'
require 'digest'
require 'omniauth-oauth2'
module OmniAuth
  module Strategies
    class BnLauncher < OmniAuth::Strategies::OAuth2

      option :name, 'bn_launcher'

      @user_id = nil

      def callback_url
        @user_id = request.params['user_id'] if request.params['user_id']
        @@user_id2 = request.params['user_id'] if request.params['user_id']
        puts request.params
        puts query_string
        puts  full_host, script_name, callback_path
        full_host + script_name + callback_path
      end

      def request_phase
        super
      end

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid{ raw_info['id'] }

      info do
        {
            :name => raw_info['name'],
            :email => raw_info['email'],
            :username => raw_info['username'],
            :provider => raw_info['provider']
        }
      end

      extra do
        {
            'raw_info' => raw_info
        }
      end

      def raw_info
        puts @user_id, "UserId"
        puts @@user_id2, "UserId"
        @raw_info ||= access_token.get("/user?user_id#{@user_id}").parsed
      end
    end
  end
end