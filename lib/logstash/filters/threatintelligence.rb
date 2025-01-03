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
      config :memcached_servers, validate: :array, default: ["memcached.service:11211"]

      def register
        begin
          @memcached_manager = MemcachedManager.new(@memcached_servers)
        rescue => e
          @logger.error("An error occurred during register: #{e.message}")
          @logger.debug("Backtrace: #{e.backtrace.join("\n")}")
          @memcached_manager = nil
        end
      end

      def filter(event)
        begin
          @key_mapping.each do |mapped_key, original_key|
            original_value = event.get(mapped_key)
            if original_value && @memcached_manager&.get("rbti:#{original_value}")
              event.set("[#{mapped_key}_is_malicious]", "malicious")
            end
          end
          filter_matched(event)
        rescue => e
          @logger.error("An error occurred in the ThreatIntelligence filter: #{e.message}")
          @logger.debug("Backtrace: #{e.backtrace.join("\n")}")
          event.set('error_message', "An error occurred while processing the threat intelligence filter")
          filter_matched(event)
        end
      end
    end
  end
end
