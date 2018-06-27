require 'omniauth'
require 'digest'
module OmniAuth
  module Strategies
    class Bn_Launcher
      include OmniAuth::Strategy
      #
      # # receive parameters from the strategy declaration and save them
      def initialize(app, secret, auth_redirect, options = {})
        @secret = secret
        @auth_redirect = auth_redirect
        @options = options
        super(app, options)
      end

      # redirect to the auth website
      def request_phase
        r = Rack::Response.new
        r.redirect request.params["redirect_uri"] || @auth_redirect
        r.finish
      end

      def callback_phase
        uid, username, email, provider, checksum = request.params["uid"], request.params["username"], request.params["email"], request.params["provider"], request.params["checksum"]
        sha1 = Digest::SHA1.hexdigest("#{@secret}#{uid}#{username}#{email}#{provider}")

        # check if the request comes from valid source or not
        if sha1 == checksum
          @uid, @username, @email, @provider = uid, username, email, provider
          # OmniAuth takes care of the rest
          super
        else
          # OmniAuth takes care of the rest
          fail!(:invalid_credentials)
        end
      end

      # normalize user's data according to http://github.com/intridea/omniauth/wiki/Auth-Hash-Schema
      def auth_hash
        OmniAuth::Utils.deep_merge(super(), {
            'uid' => @uid,
            'user_info' => {
                'username' => @username,
                'email'    => @email,
                'provider' => @provider
            }
        })
      end
    end
  end
end