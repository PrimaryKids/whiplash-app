module Whiplash
  class App
    module Connections

      def base_app_request(options={})
        if options[:params][:id]
          endpoint = [options[:endpoint], options[:params].delete(:id)].join('/')
        else
          endpoint = options[:endpoint]
        end
        options[:headers] ||= {}
        options[:headers][:customer_id] ||= customer_id if customer_id
        options[:headers][:shop_id] ||= shop_id if shop_id

        args = [
          options[:method],
          endpoint,
          options[:params],
          sanitize_headers(options[:headers])
        ]

        connection.send(*args)
      end

      def app_request(options={})
        return base_app_request(options) unless defined?(Sidekiq)
        limiter = Sidekiq::Limiter.window('whiplash-core', self.rate_limit, :second, wait_timeout: 15)
        limiter.within_limit do
          base_app_request(options)
        end
      end

      def app_request!(options = {})
        begin
          response = app_request(options)
        rescue Faraday::ConnectionFailed => e
          case e.message
          when 'end of file reached'
            store_whiplash_error!(:eof, options)
            Rails.logger.error "[Whiplash][EOF] Failed to connect to #{url}"
            raise ProviderError::InternalServerError, e.message
          when 'Net::OpenTimeout'
            store_whiplash_error!(:timeout, options)
            Rails.logger.error "[Whiplash][Timeout] Request to #{url} timed out"
            raise ProviderError::Timeout, e.message
          else
            store_whiplash_error!(:connection, options)
            Rails.logger.error "[Whiplash] Request to #{url} failed"
            raise ProviderError::InternalServerError, e.message
          end
        end
        return response.body if response.success?
        message = response.body if response.body.is_a? String
        message = response.body.dig('error') if response.body.respond_to?(:dig)
        store_whiplash_error!(response.status)
        error_response(response.status, message)
      end

      def delete(endpoint, params = {}, headers = nil)
        app_request(method: :delete,
                    endpoint: endpoint,
                    params: params,
                    headers: headers)
      end

      def get(endpoint, params = {}, headers = nil)
        app_request(method: :get,
                    endpoint: endpoint,
                    params: params,
                    headers: headers)
      end

      def post(endpoint, params = {}, headers = nil)
        app_request(method: :post,
                    endpoint: endpoint,
                    params: params,
                    headers: headers)
      end

      def put(endpoint, params = {}, headers = nil)
        app_request(method: :put,
                    endpoint: endpoint,
                    params: params,
                    headers: headers)
      end

      def delete!(endpoint, params = {}, headers = nil)
        app_request!(method: :delete,
                    endpoint: endpoint,
                    params: params,
                    headers: headers)
      end

      def get!(endpoint, params = {}, headers = nil)
        app_request!(method: :get,
                    endpoint: endpoint,
                    params: params,
                    headers: headers)
      end

      def post!(endpoint, params = {}, headers = nil)
        app_request!(method: :post,
                    endpoint: endpoint,
                    params: params,
                    headers: headers)
      end

      def put!(endpoint, params = {}, headers = nil)
        app_request!(method: :put,
                    endpoint: endpoint,
                    params: params,
                    headers: headers)
      end

      def sanitize_headers(headers)
        if headers
          {}.tap do |hash|
            headers.each do |k,v|
              hash["X-#{k.to_s.upcase.gsub('_','-')}"] = v.to_s
            end
          end
        end
      end

      def store_whiplash_error!(error, options={})
        return unless defined?(Appsignal)
        options = options.with_indifferent_access
        Appsignal.increment_counter(
          "whiplash_error",
          1.0,
          shop_id: options[:shop_id],
          customer_id: options[:customer_id],
          error: error.to_s
        )
      end

      def error_codes
        WhiplashApiError.codes
      end

      def select_error(status_code)
        unless error_codes.keys.include? status_code
          Rails.logger.info "[Provider] Unknown status code from #{self.class.name}: #{status_code}"
          return WhiplashApiError::UnknownError
        end
        error_codes[status_code]
      end

      # Select an applicable error message on a request to a provider.
      def error_response(status_code, message=nil)
        message ||= "Your request has been denied as a #{status_code} error"
        raise select_error(status_code), message
      end

    end
  end
end
