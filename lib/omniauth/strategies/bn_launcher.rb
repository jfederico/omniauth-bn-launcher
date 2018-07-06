require 'omniauth'
require 'digest'
require 'omniauth-oauth2'
module OmniAuth
  module Strategies
    class BnLauncher < OmniAuth::Strategies::OAuth2

      option :name, 'bn_launcher'
      option :customer, nil
      option :default_callback_url

      def request_phase
        session["omniauth.redirect_url"] = request.protocol + request.host_with_port
        options.authorize_params[:customer] = options[:customer]
        super
      end

      def callback_url
        if options[:default_callback_url].nil?
          fail!(:callback_url_not_set, "The callback url is not set")
        end
        options[:default_callback_url] + script_name + callback_path + query_string
      end

      def redirect_url
        if session["omniauth.redirect_url"].nil?
          fail!(:redirect_url_not_set, "The redirect url is not set")
        end
        session["omniauth.redirect_url"] + script_name + callback_path + query_string
      end

      def callback_phase
        if request.host == options[:default_callback_url]
          response = Rack::Response.new
          response.redirect redirect_url
          response.finish
        else
          super
        end
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