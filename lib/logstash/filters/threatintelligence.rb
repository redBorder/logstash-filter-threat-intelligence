# frozen_string_literal: true

# logstash-filter-threat-intelligence.rb

require 'dalli'
require 'logstash/filters/base'
require 'logstash/namespace'

require_relative 'utils/data_cache'
require_relative 'utils/memcached_config'

module LogStash
  module Filters
    #
    # Base filter to enrich events with threat intelligence data
    #
    class ThreatIntelligence < LogStash::Filters::Base
      config_name 'threatintelligence'

      config :key_mapping, validate: :hash, default: {}

      def register
        @memcached_servers = MemcachedConfig.servers
        @memcached_manager = MemcachedManager.new(@memcached_servers)
      end

      def filter(event)
        @key_mapping.each do |mapped_key, original_key|
          if @memcached_manager.get("rbti:#{event.get(original_key)}")
            event.set("[#{mapped_key}_malicious]", "true")
          end
        end

        filter_matched(event)
      end
    end
  end
end
