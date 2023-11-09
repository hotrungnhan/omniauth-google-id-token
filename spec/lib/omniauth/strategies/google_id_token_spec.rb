require 'spec_helper'
require 'multi_json'
require 'jwt'

describe OmniAuth::Strategies::GoogleIdToken do # rubocop:disable Metrics/BlockLength
  let(:rsa_private) { OpenSSL::PKey::RSA.generate 512 }
  let(:rsa_public) { rsa_private.public_key }

  let(:response_json) { MultiJson.load(last_response.body) }
  let(:id_token) { 'tokensss' }
  let(:payload) do
    { 'iss' => 'https://accounts.google.com',
      'nbf' => 161_803_398_874,
      'aud' => 'http://example.com',
      'sub' => '3141592653589793238',
      'hd' => 'gmail.com',
      'email' => 'bob@example.com',
      'email_verified' => true,
      'azp' => '314159265-pi.apps.googleusercontent.com',
      'name' => 'Elisa Beckett',
      'picture' => 'https://lh3.googleusercontent.com/a-/e2718281828459045235360uler',
      'given_name' => 'Elisa',
      'family_name' => 'Beckett',
      'iat' => 1_596_474_000,
      'exp' => 1_596_477_600,
      'jti' => 'abc161803398874def' }
  end
  let(:aud_claim) { payload[:aud] }
  let(:azp_claim) { payload[:azp] }

  let(:client_id) { 'test_client_id' }
  let(:args) do
    [
      {
        aud_claim: payload[:aud],
        azp_claim: payload[:azp],
        client_id: client_id
      }
    ]
  end

  let(:app)  do
    the_args = args
    Rack::Builder.new do |b|
      b.use Rack::Session::Cookie, secret: 'sekrit'
      b.use OmniAuth::Strategies::GoogleIdToken, *the_args
      b.run ->(env) { [200, {}, [(env['omniauth.auth'] || {}).to_json]] }
    end
  end

  let(:api_url) { '/auth/google_id_token' }

  describe 'Subclassing Behavior' do
    subject { fresh_strategy }

    it 'performs the OmniAuth::Strategy included hook' do
      expect(OmniAuth.strategies).to include(OmniAuth::Strategies::GoogleIdToken)
    end
  end

  describe 'request phase' do
    it 'should redirect to the configured login url' do
      post api_url
      expect(last_response.status).to eq(302)
      expect(last_response.headers['Location'].gsub(/&state=[0-9a-z]*/,
                                                    '')).to eq('https://accounts.google.com/o/oauth2/auth?scope=profile%20email%20openid&access_type=offline&include_granted_scopes=true&redirect_uri=http%3A%2F%2Fexample.org%2Fauth%2Fgoogle_id_token%2Fcallback&response_type=token%20id_token&client_id=test_client_id')
      # Removed state random field
    end
  end

  context 'callback phase' do
    it 'should decode the response' do
      allow(::Google::Auth::IDTokens::Verifier).to receive(:verify_oidc)
        .with(id_token, aud: aud_claim, azp: azp_claim)
        .and_return(payload)

      post "#{api_url}/callback", id_token: id_token
      expect(response_json['info']['email']).to eq('bob@example.com')
    end

    it 'should not work without required fields' do
      payload.delete('email')
      allow(::Google::Auth::IDTokens::Verifier).to receive(:verify_oidc)
        .with(id_token, aud: aud_claim, azp: azp_claim)
        .and_return(payload)

      post "#{api_url}/callback", id_token: id_token
      expect(last_response.status).to eq(302)
    end

    it 'should assign the uid' do
      allow(::Google::Auth::IDTokens::Verifier).to receive(:verify_oidc)
        .with(id_token, aud: aud_claim, azp: azp_claim)
        .and_return(payload)
      post "#{api_url}/callback", id_token: id_token
      expect(response_json['uid']).to eq('3141592653589793238')
    end
  end
end
