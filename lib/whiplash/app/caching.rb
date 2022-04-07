module Whiplash
  class App
    module Caching

      def cache_store
        Rails.cache
      end

      def self.namespace_value
        ENV["REDIS_NAMESPACE"] || ENV["WHIPLASH_CLIENT_ID"]
      end
    end
  end
end
