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
      config_name 'threat_intelligence'

      config :indicators_types, validate: :hash, default: {}
      config :memcached_servers, validate: :array, default: ["memcached.service:11211"]
      config :key_prefix, validate: :string, default: "rbti"
      config :sensors_policies, validate: :hash, required: true

      def register
        begin
          @memcached_manager = MemcachedManager.new(@memcached_servers)

           # Parse sensor_policies
           @sensors_policies.each do |sensor_name, policy|
            next unless policy.is_a?(String)

            @sensors_policies[sensor_name] = JSON.parse(policy)
          end

          # Clean @indicators_types
          allowed_types = ["ip", "domain", "url", "sha1", "sha2"]
          @indicators_types  = @indicators_types.select { |_, v| allowed_types.include?(v) }

        rescue => e
          @logger.error("Error initializing Memcached client: #{e.message}")
          @logger.error("Error parsing sensors_policies JSON: #{e.message}")
          @logger.debug("Backtrace: #{e.backtrace.join("\n")}")
          @memcached_manager = nil
        end
      end

      def filter(event)
        begin
          return unless @memcached_manager

          return unless @sensors_policies && @sensors_policies.any?

          sensor_name = event.get('sensor_name')
          return unless sensor_name && !sensor_name.empty?

          sensor_policy = @sensors_policies[sensor_name]
          return unless sensor_policy['id'] && sensor_policy['name'] && sensor_policy['threshold']

          ti_policy_id = sensor_policy['id'].to_s
          ti_policy_name = sensor_policy['name'].to_s
          ti_policy_threshold = sensor_policy['threshold'].to_f rescue 0
          ti_category = 'clean'
          ti_score = 0
          ti_indicators = nil

          indicators = {}

          @indicators_types.keys.each do |key|
            value = event.get(key)
            indicators[key] = value if value && !value.to_s.empty?
          end

          clean_indicators = []
          malicious_indicators = []
          weights = {}

          indicators.each do |indicator, value|
            next unless value && !value.to_s.empty?

            next unless @indicators_types[indicator] # Ensure the indicator is in the mapping

            # Firt we check if the key is clean
            memcached_key = "#{@key_prefix}:#{ti_policy_id}:c:#{@indicators_types[indicator]}:#{value.to_s}"
            @logger.debug("Checking if memcached key is clean: #{memcached_key} ...")
            memcached_value = @memcached_manager.get(memcached_key)

            if memcached_value
              @logger.debug("Key #{memcached_key} is clean.")
              clean_indicators << indicator
              next
            end

            # Then we check if key is malicious
            memcached_key = "#{@key_prefix}:#{ti_policy_id}:m:#{value.to_s}"
            @logger.debug("Checking if memcached key is malicious: #{memcached_key} ...")
            memcached_value = @memcached_manager.get(memcached_key)
            next unless memcached_value

            @logger.debug("Key #{memcached_key} is malicious.")
            malicious_indicators << indicator

            # Clean memcached value
            memcached_value = memcached_value.to_s.strip

            # Calculate weight
            if memcached_value == "1"
              weights[indicator] = 1.0
            else
              # If the value is a JSON object, parse it to get the weight
              next unless @indicators_types[indicator] == 'ip'

              begin
                details = JSON.parse(memcached_value)
                next unless details['weight']

                weights[indicator] = details['weight'].to_f
              rescue JSON::ParserError
                @logger.debug("Invalid JSON in Memcached for #{memcached_key}")
              end
            end
          end

          malicious_indicators = malicious_indicators - clean_indicators

          if malicious_indicators.any?

            # Calculate score in case there are weights or 100 (default malicious max score)
            ti_score = weights.any? ? (weights.values.max * 100).round(2) : 100

            if ti_score >= ti_policy_threshold
              ti_category = 'malicious'
              ti_indicators = malicious_indicators.uniq.join(', ')
            end
          end

          event.set('ti_policy_id', ti_policy_id)
          event.set('ti_policy_name', ti_policy_name)
          event.set('ti_category', ti_category)
          event.set('ti_score', ti_score)
          event.set('ti_indicators', ti_indicators) if ti_indicators

          filter_matched(event)

        rescue => e
          @logger.error("Exception in Threat Ingeligence filter: #{e.message}")
          @logger.debug("Backtrace: #{e.backtrace.join("\n")}")
          event.set('error_message', "An error occurred in Threat Ingeligence filter")
          filter_matched(event)
        end
      end
    end
  end
end
