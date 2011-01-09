# Ruby 1.9.x requirements.
if RUBY_VERSION =~ /^1.9/
  # The net-ldap gem uses String#to_a. In Ruby 1.9.x this needs to be
  # String.lines.to_a, but I have to monkey patch this in for things to work.
  class String
    def to_a
      self.lines.to_a
    end
  end
end

require 'yaml'
gem 'net-ldap', '= 0.1.1'
require 'net/ldap'

require 'radum/logger'
require 'radum/ad'
require 'radum/container'
require 'radum/group'
require 'radum/user'
