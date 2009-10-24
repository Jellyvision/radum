#!/usr/bin/env ruby -I ../lib

puts "Testing with Ruby version #{RUBY_VERSION}\n\n"

require 'rubygems'
# Tests are automatically run just by requiring these.
require 'tc_container'
require 'tc_group'
require 'tc_user'
require 'tc_unix_user'
require 'tc_ad'
