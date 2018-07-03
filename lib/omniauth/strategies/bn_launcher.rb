require 'omniauth'
require 'digest'
require 'omniauth-oauth2'
module OmniAuth
  module Strategies
    class BnLauncher < OmniAuth::Strategies::OAuth2

      option :name, 'bn_launcher'

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
        puts session[:user_id]
        puts env
        @raw_info ||= access_token.get('/user').parsed
      end
    end
  end
end