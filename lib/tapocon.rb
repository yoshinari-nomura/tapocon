# frozen_string_literal: true

# TP-Link TAPO P105 client in Ruby
# Yoshinari Nomura 2024-12-09 nom@quickhack.net
#
# Original Python version:
#   GitHub almottier/TapoP100
#   https://github.com/almottier/TapoP100

module Tapocon
  class Error < StandardError; end

  dir = File.dirname(__FILE__) + '/tapocon'
  autoload :Scanner,      "#{dir}/scanner.rb"
  autoload :Switch,       "#{dir}/switch.rb"
  autoload :Version,      "#{dir}/version.rb"
  autoload :MQTT,         "#{dir}/mqtt.rb"
end
