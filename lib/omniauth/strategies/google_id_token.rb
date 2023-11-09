require 'omniauth'
require 'googleauth'
module OmniAuth
  module Strategies
    class GoogleIdToken
      include OmniAuth::Strategy

      class ClaimInvalid < StandardError; end

      def self.inherited(subclass) # rubocop:disable Lint/MissingSuper
        OmniAuth::Strategy.included(subclass)
      end

      BASE_SCOPES = %w[profile email openid].freeze
      RESPONSE_TYPES = %w[token id_token].freeze

      option :name, 'google_id_token'
      option :uid_claim, 'sub'
      option :client_id, nil # Required for request_phase e.g. redirect to auth page
      option :aud_claim, nil
      option :azp_claim, nil
      option :iss_claim, nil
      option :required_claims, %w[email]
      option :info_map, { 'name' => 'name', 'email' => 'email' }

      def request_phase
        redirect URI::HTTPS.build(host: 'accounts.google.com', path: '/o/oauth2/auth', query: URI.encode_www_form(authorize_params)).to_s.gsub( # rubocop:disable Layout/LineLength
          /\+/, '%20'
        )
      end

      def authorize_params # rubocop:disable Metrics/AbcSize
        params = {}
        params[:scope] = BASE_SCOPES.join(' ')
        params[:access_type] = 'offline'
        params[:include_granted_scopes] = true
        params[:state] = SecureRandom.hex(24)
        session['omniauth.state'] = params[:state]
        params[:redirect_uri] = callback_url
        params[:response_type] = RESPONSE_TYPES.join(' ')
        params[:client_id] = options.client_id
        params
      end

      def decoded # rubocop:disable Metrics/AbcSize,Metrics/MethodLength
        unless @decoded
          begin
            @decoded = validator.verify_oidc(request.params['id_token'], aud: options.aud_claim, azp: options.azp_claim)
          rescue StandardError => e
            raise ClaimInvalid, e.message
          end
        end

        (options.required_claims || []).each do |field|
          raise ClaimInvalid, "Missing required '#{field}' claim." unless @decoded.key?(field.to_s)
        end
        @decoded
      end

      def callback_phase
        super
      rescue ClaimInvalid => e
        fail! :claim_invalid, e
      end

      uid do
        decoded[options.uid_claim]
      end

      extra do
        { raw_info: decoded }
      end

      info do
        options.info_map.each_with_object({}) do |(k, v), h|
          h[k.to_s] = decoded[v.to_s]
        end
      end

      private

      def validator
        ::Google::Auth::IDTokens::Verifier
      end

      def uid_lookup
        @uid_lookup ||= options.uid_claim.new(request)
      end
    end
  end
end
