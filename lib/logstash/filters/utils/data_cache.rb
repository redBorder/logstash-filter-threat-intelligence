# frozen_string_literal: true

#
# Class to manage memcached get/set
#
class MemcachedManager
  def initialize(memcached_servers)
    @memcached = Dalli::Client.new(memcached_servers)
  end

  def fetch_cached_data(key)
    @memcached.get(key)
  end
end
