require 'spec_helper'
require 'digest'

def post_response(user, checksum)
  post '/auth/bn_launcher/callback', user.merge({:checksum => checksum})
end

RSpec::Matchers.define :fail_with do |message|
  match do |actual|
    actual.redirect? && /\?.*message=#{message}/ === actual.location
  end
end

RSpec.describe OmniAuth::Strategies::BnLauncher do
  include OmniAuth::Test::StrategyTestCase
  let(:sample_user) {
    {
        uid:'1233',
        username: 'user user',
        email:'user@email.com',
        provider: 'sample_provider'
    }
  }
  let(:secret){"someSEcREt"}
  let(:auth_hash){ last_request.env['omniauth.auth'] }
  let(:strategy) { [OmniAuth::Strategies::BnLauncher, secret, "https://idp.sso.example.com/signon/0609"] }

  it "has a version number" do
    expect(OmniAuth::Bn::Launcher::VERSION).not_to be nil
  end


  describe 'GET /auth/bn_launcher' do
    context 'without redirect uri present' do
      before do
        get '/auth/bn_launcher'
      end

      it 'should redirect to authentication uri passed when initialized' do
        expect(last_response).to be_redirect
        expect(last_response.location).to match /https:\/\/idp.sso.example.com\/signon\/0609/
      end
    end

    context 'with redirect uri present' do
      before do
        get '/auth/bn_launcher?redirect_uri=https://test.other.idp.com'
      end

      it 'should redirect to authentication uri passed as a param' do
        expect(last_response).to be_redirect
        expect(last_response.location).to match /https:\/\/test.other.idp.com/
      end
    end
  end


  describe 'POST /auth/bn_launcher/callback' do
    context 'callback initiated with valid checksum' do
      before do
        post_response(sample_user, Digest::SHA1.hexdigest("#{secret}#{sample_user[:uid]}#{sample_user[:username]}#{sample_user[:email]}#{sample_user[:provider]}"))
      end

      it 'should have the correct auth params when passed the correct secret' do
        expect(auth_hash['uid']).to eq sample_user[:uid]
        expect(auth_hash['user_info']['username']).to eq sample_user[:username]
        expect(auth_hash['user_info']['email']).to eq sample_user[:email]
        expect(auth_hash['user_info']['provider']).to eq sample_user[:provider]
      end
    end

    context 'callback initiated with invalid checksum' do
      before do
        post_response(sample_user, 'invalid checksum')
      end

      it 'is expected to fail with invalid credentials' do
        expect(last_response).to fail_with(:invalid_credentials)
      end
    end
  end

end
