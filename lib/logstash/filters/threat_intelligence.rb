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

      config :memcached_servers, validate: :array, default: ["memcached.service:11211"]
      config :indicators_mapping, validate: :hash, default: {}
      config :sensors_policies, validate: :hash, required: true
      config :key_prefix, validate: :string, default: "rbti"

      def register
        begin
          @memcached_manager = MemcachedManager.new(@memcached_servers)

          # Parse sensor_policies
          @sensors_policies.each do |sensor_name, policy|
            next unless policy.is_a?(Hash)
  
            allowed_policies_attributes = ['id', 'name', 'threshold_ip', 'threshold_domain', 'threshold_url', 'threshold_sha1', 'threshold_sha2']
            @sensors_policies[sensor_name] = policy.select {|k, _| allowed_policies_attributes.include?(k) } 
          end

          # Clean @indicators_mapping
          @allowed_indicators_types = ['ip', 'domain', 'url', 'sha1', 'sha2']
          @indicators_mapping  = @indicators_mapping.select { |_, v| @allowed_indicators_types.include?(v) }

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

          return unless @indicators_mapping.any?

          sensor_name = event.get('sensor_name')
          return unless sensor_name && !sensor_name.empty?

          sensor_policy = @sensors_policies[sensor_name]
          unless sensor_policy
            @logger.debug("No policy found for sensor_name: #{sensor_name}")
            return
          end
          return unless sensor_policy['id'] && sensor_policy['name']

          ti_policy_id = sensor_policy['id'].to_s
          ti_policy_name = sensor_policy['name'].to_s
          ti_category = 'clean'
          ti_score = 0
          ti_indicators = []

          thresholds = {}
          @allowed_indicators_types.each do |indicator_type|
            thresholds[indicator_type] = sensor_policy["threshold_#{indicator_type}"] || 0
          end

          indicators = {}
          @indicators_mapping.keys.each do |key|
            value = event.get(key)
            indicators[key] = value if value && !value.to_s.empty?
          end

          clean_indicators = []
          malicious_indicators = []
          weights = {}

          indicators.each do |indicator, value|
            next unless value && !value.to_s.empty?

            next unless @indicators_mapping[indicator] # Ensure the indicator is in the mapping

            # First we check if the key is clean
            memcached_key = "#{@key_prefix}:#{ti_policy_id}:#{@indicators_mapping[indicator]}:c:#{value.to_s}"
            @logger.debug("Checking if memcached key is clean: #{memcached_key} ...")

            if @memcached_manager.get(memcached_key) 
              @logger.debug("Key #{memcached_key} is clean.")
              clean_indicators << indicator
              next
            end

            # Then we check if key is malicious
            memcached_key = "#{@key_prefix}:#{ti_policy_id}:#{@indicators_mapping[indicator]}:m:#{value.to_s}" 
            @logger.debug("Checking if memcached key is malicious: #{memcached_key} ...")
            weight = @memcached_manager.get(memcached_key)
            next unless weight

            @logger.debug("Key #{memcached_key} is malicious.")
            malicious_indicators << indicator

            # Convert weight to float safely
            weight = weight.to_f rescue 0
            weights[indicator] = weight
          end

          malicious_indicators = malicious_indicators - clean_indicators

          total_score = 0
          malicious_indicators.each do |indicator|
            indicator_type = @indicators_mapping[indicator]
            next unless indicator_type

            threshold = thresholds[indicator_type]
            next unless threshold

            weight = weights[indicator]
            next unless weight

            score = weight * 100
            
            @logger.debug("Indicator #{indicator} of type #{indicator_type} has weight #{weight}, score #{score}, threshold #{threshold}")

            if score >= threshold
              ti_category = 'malicious'
              ti_indicators.push(indicator)
              total_score = total_score + score
            end
          end

          event.set('ti_policy_id', ti_policy_id)
          event.set('ti_policy_name', ti_policy_name)
          event.set('ti_category', ti_category)

          if ti_indicators.any?
            ti_average_score = ti_indicators.count > 0 ? (total_score / ti_indicators.count) : 0
            ti_average_score = ti_average_score.round(2)
            ti_indicators = ti_indicators.uniq.join(', ')

            event.set('ti_average_score', ti_average_score)
            event.set('ti_indicators', ti_indicators)
          end

        rescue => e
          @logger.error("Exception in Threat Intelligence filter: #{e.message}")
          @logger.debug("Backtrace: #{e.backtrace.join("\n")}")
          event.set('error_message', "An error occurred in Threat Intelligence filter")
        ensure
          filter_matched(event)
        end
      end
    end
  end
end
