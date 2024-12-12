# frozen_string_literal: true

require 'json'
require 'logger'
require 'net/http'
require 'openssl'
require 'securerandom'

$LOGLEVEL = Logger::ERROR
# $LOGLEVEL = Logger::DEBUG

$DEBUG = ($LOGLEVEL == Logger::DEBUG)

module Tapocon
  def dump_hex(str)
    str.each_byte.map{|f| "%02x" % f}.join(' ')
  end

  class Cipher
    attr_reader :local_seed, :sequence

    def initialize(username, password, logger = nil)
      @username, @password = username, password
      @local_seed = SecureRandom.random_bytes(16)
      @aes_key, @aes_iv, @sequence, @signature = nil, nil, nil, nil
      @logger = logger || Logger.new(nil)
    end

    def aes_setup(handshake_key)
      remote_seed = handshake_key[0, 16] # 16B seed
      server_hash = handshake_key[16..] # SHA256 (32B)

      puts "remote_seed: #{dump_hex(remote_seed)}" if $DEBUG
      puts "server_hash: #{dump_hex(server_hash)}" if $DEBUG

      credentials = [
        [@username, @password],
        ['', ''],
        ['kasa@tp-link.net', 'kasaSetup'],
      ]

      auth_hash = nil
      credentials.each do |username, password|
        @logger.debug("Try Auth: #{username}, #{password}")
        ah = calc_auth_hash(username, password)
        if sha256(@local_seed + remote_seed + ah) == server_hash
          auth_hash = ah
          @logger.debug("Authenticated with #{username}")
          break
        end
      end
      raise "Failed to authenticate" unless auth_hash

      combined_seed = @local_seed + remote_seed + auth_hash
      @aes_key = sha256("lsk".b + combined_seed)[0, 16]
      ivseq = sha256("iv".b + combined_seed)
      @aes_iv = ivseq[0, 12]
      @sequence = ivseq[-4, 4].unpack1("N") # uint32 big endian
      @signature = sha256("ldk".b + combined_seed)[0, 28]
      @logger.debug("Initialized")

      res = sha256(remote_seed + @local_seed + auth_hash)
      return res
    end

    def encrypt(data)
      raise "Cipher not initialized" unless @aes_key && @aes_iv && @signature

      @sequence += 1
      seq = [@sequence].pack("N")

      pad_size = 16 - (data.bytesize % 16)
      padded_data = data + (pad_size.chr * pad_size)

      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      cipher.key = @aes_key
      cipher.iv = @aes_iv + seq

      bin = cipher.update(padded_data) + cipher.final
      sig = sha256(@signature + seq + bin)
      sig + bin
    end

    def decrypt(data)
      raise "Cipher not initialized" unless @aes_key && @aes_iv && @sequence

      seq = [@sequence].pack("N")

      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.decrypt
      cipher.key = @aes_key
      cipher.iv = @aes_iv + seq

      decrypted_data = cipher.update(data[32..]) + cipher.final

      if $DEBUG
        # padding seems to be already removed
        puts "decrypted_data size: #{decrypted_data.size}"
        puts "pad size: #{decrypted_data[-1].ord}"
      end
      decrypted_data
    end

    private

    def sha1(data)
      OpenSSL::Digest::SHA1.digest(data)
    end

    def sha256(data)
      OpenSSL::Digest::SHA256.digest(data)
    end

    def calc_auth_hash(username, password)
      sha256(sha1(username) + sha1(password))
    end
  end # class Cipher

  class Switch
    def initialize(ip, username, password)
      @logger = Logger.new(STDOUT, level: $LOGLEVEL)
      @ip = ip
      @cipher = Cipher.new(username, password, @logger)
      @cookie = nil
    end

    def handshake
      handshake1_key = rpc_raw(:handshake1, @cipher.local_seed)
      handshake2_key = @cipher.aes_setup(handshake1_key)
      res = rpc_raw(:handshake2, handshake2_key)
    end

    def turn_on(delay: 0)
      turn_to(true, delay: delay)
    end

    def turn_off(delay: 0)
      turn_to(false, delay: delay)
    end

    def toggle(delay: 0)
      if on?
        turn_off(delay: delay)
      else
        turn_on(delay: delay)
      end
    end

    def turn_to(state, delay: 0)
      if delay > 0
        rpc(:add_countdown_rule,
            delay: delay,
            desired_states: state ? :on : :off)
      else
        rpc(:set_device_info,
            device_on: state)
      end
    end

    def on?
      info()['device_on'] == true
    end

    def info
      rpc(:get_device_info)
    end

    private

    # XXX: WIP: connection pool for keep-alive?
    def http_connect(uri)
      return @connection if @connection
      @connection = Net::HTTP.new(uri.host, uri.port, nil, nil)
      @connection.use_ssl = (uri.scheme == 'https')
      @connection.open_timeout = 1.5
      @connection.read_timeout = 1.5
      @connection.keep_alive_timeout = 5
      @connection.start
    end

    def rpc_raw(name, data, **params)
      uri = URI("http://#{@ip}/app/#{name}")
      uri.query = URI.encode_www_form(params) unless params.empty?
      connection = http_connect(uri)

      req = Net::HTTP::Post.new(uri)
      req.content_type = 'application/octet-stream'
      req.body = data
      req['Connection'] = 'Keep-Alive'
      req['User-Agent'] = 'python-requests/2.25.1'
      req['Accept-Encoding'] = 'gzip, deflate'
      req['Accept'] = '*/*'

      if @cookie
        puts "Cookie: #{@cookie}" if $DEBUG
        req['Cookie'] = @cookie
      end

      res = connection.request(req)

      if $DEBUG
        puts "URI: #{uri}"
        puts "Request: #{req}"
        puts "HTTP Method: #{req.method}"
        puts "Headers:"
        req.each_header { |key, value| puts "#{key}: #{value}" }
        query_params = uri.query
        puts "Query Parameters: '#{query_params}'"
      end

      if res['Set-Cookie']
        @cookie = res['Set-Cookie'].sub(/;.*$/, '')
      end

      if $DEBUG
        puts "RPC_RAW result:"
        puts "code: #{res.code}, body-size: #{res.body.size}"
        puts "body: #{dump_hex(res.body)}"
        puts "body_raw: #{res.body}"
      end
      return res.body
    end

    def rpc(name, **params)
      req = {method: name}
      req.merge!(params: params) unless params.empty?

      @logger.debug("Request: #{req.to_json}")
      res = rpc_raw(:request, @cipher.encrypt(req.to_json),
                    seq: @cipher.sequence)

      data = JSON.parse(@cipher.decrypt(res))
      @logger.debug("Response: #{data}")

      if data['error_code'] != 0
        @logger.error("Error: #{data}")
        @aes_key = nil
        raise "Error code: #{data['error_code']}"
      end
      data['result']
    end
  end # class P100
end # module Tapo

# Example usage
if __FILE__ == $PROGRAM_NAME
  tapo = Tapocon::Switch.new("192.168.11.31", "alice@example.com", "password")
  tapo.handshake
  puts tapo.info

  while true
    tapo.toggle
    sleep(5)
  end
end
