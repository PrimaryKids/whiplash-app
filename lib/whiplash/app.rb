require 'whiplash/app/api_config'
require 'whiplash/app/caching'
require 'whiplash/app/connections'
require 'whiplash/app/finder_methods'
require 'whiplash/app/signing'
require 'whiplash/app/version'
require 'errors/whiplash_api_error'
require 'oauth2'
require 'faraday_middleware'

module Whiplash
  class App
    include Whiplash::App::ApiConfig
    include Whiplash::App::Caching
    include Whiplash::App::Connections
    include Whiplash::App::FinderMethods
    extend Whiplash::App::Signing

    WHIPLASH_AUTH_CODE_KEY = 'whiplash_auth_code'
    WHIPLASH_API_KEY = 'whiplash_auth_token'

    attr_accessor :customer_id, :shop_id, :token

    def initialize(token = nil, options = {})
      token ||= cache_store.read(WHIPLASH_API_KEY)
      @token = format_token(token) unless token.nil?
      @customer_id = options[:customer_id]
      @shop_id = options[:shop_id]
      @api_version = options[:api_version] || 2 # can be 2_1
      @callback = options[:callback]
    end

    def self.whiplash_api_token
      Rails.cache.read(WHIPLASH_API_KEY)
    end

    def client
      OAuth2::Client.new(ENV['WHIPLASH_CLIENT_ID'], ENV['WHIPLASH_CLIENT_SECRET'], site: api_url)
    end

    def versioned_api_url
      "api/v#{@api_version}"
    end

    def connection
      Faraday.new [api_url, versioned_api_url].join('/') do |conn|
        conn.request :oauth2, token.token, token_type: 'bearer'
        conn.request :json
        conn.response :json, content_type: /\bjson$/
        conn.use :instrumentation
        conn.adapter Faraday.default_adapter
      end
    end

    def token=(oauth_token)
      instance_variable_set('@token', format_token(oauth_token))
    end

    def refresh_token!
      unless Rails.cache.read(WHIPLASH_AUTH_CODE_KEY) || !token.nil?
        raise StandardError,
              "rails cache value #{WHIPLASH_AUTH_CODE_KEY} not set"
      end
      if !token && Rails.cache.read(WHIPLASH_AUTH_CODE_KEY)
        begin
          access_token = client.auth_code.get_token(Rails.cache.read(WHIPLASH_AUTH_CODE_KEY), redirect_uri: @callback)


        rescue URI::InvalidURIError => e
          raise StandardError, "The provide URL (#{ENV['WHIPLASH_API_URL']}) is not valid"
        end
      else
        raise StandardError, 'You must request an access token before you can refresh it' if token.nil?

        unless token.is_a?(OAuth2::AccessToken)
          raise StandardError,
                'Token must either be a Hash or an OAuth2::AccessToken'
        end

        access_token = token.refresh!
      end
      Rails.cache.delete(WHIPLASH_AUTH_CODE_KEY)
      new_token = access_token.to_hash
      cache_store.write(WHIPLASH_API_KEY, new_token)
      self.token = access_token
    end

    def token_expired?
      return token.expired? unless token.nil?
      return true unless cache_store.read(WHIPLASH_API_KEY)
      return true if cache_store.read(WHIPLASH_API_KEY).nil?
      return true if cache_store.read(WHIPLASH_API_KEY).empty?

      false
    end

    private

    def format_token(oauth_token)
      return oauth_token if oauth_token.is_a?(OAuth2::AccessToken)
      raise StandardError, 'Token must either be a Hash or an OAuth2::AccessToken' unless oauth_token.is_a?(Hash)

      oauth_token['expires'] = oauth_token['expires'].to_s # from_hash expects 'true'
      if oauth_token.key?('token')
        oauth_token['access_token'] = oauth_token['token']
        oauth_token.delete('token')
      end
      OAuth2::AccessToken.from_hash(client, oauth_token)
    end
  end
end
