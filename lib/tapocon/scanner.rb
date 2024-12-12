#!/usr/bin/env ruby

# Find HS105 (legacy) and P105 (new)
# https://github.com/python-kasa/python-kasa/blob/master/kasa/discover.py#L169

require 'socket'
require 'openssl'
require 'securerandom'
require 'json'
require 'zlib'

module Tapocon
  class Scanner
    def initialize
      @socket = UDPSocket.new
      @socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, true)
    end

    def scan
      scan_new_devices(@socket)
      scan_old_devices(@socket)
    end

    private

    def scan_old_devices(socket)
      addr, port = '255.255.255.255', 9999
      cipher = Cipher.new
      msg = cipher.xor_encrypt('{"system": {"get_sysinfo": null}}')

      socket.send(msg, 0, addr, port)
      socket.timeout = 3

      res = nil
      begin
        res, sender = socket.recvfrom(1024)
        res = cipher.xor_decrypt(res)
        puts "Received response from #{sender}: #{res}"
      rescue IO::WaitReadable, Errno::ETIMEDOUT
        puts "No response received within timeout period."
      ensure
        # socket.close
      end
      return res
    end

    def scan_new_devices(socket)
      addr, port = '255.255.255.255', 20002
      msg = QueryGenerator.new.generate_query

      socket.send(msg, 0, addr, port)
      socket.timeout = 3

      res = nil
      begin
        res, sender = socket.recvfrom(1024)
        res = res[16..]
        puts "Received response from #{sender}: #{res}"
      rescue IO::WaitReadable, Errno::ETIMEDOUT
        puts "No response received within timeout period."
      ensure
        # socket.close
      end
      return res
    end

    class Cipher
      INITIAL_KEY = 171

      def xor_encrypt(data, key = INITIAL_KEY)
        data.bytes.map do |byte|
          key = byte ^ key
        end.pack("C*")
      end

      def xor_decrypt(data, key = INITIAL_KEY)
        data.bytes.map do |byte|
          result = byte ^ key
          key = byte
          result
        end.pack("C*")
      end
    end

    class QueryGenerator
      def initialize
        @keys = OpenSSL::PKey::RSA.new(2048)
      end

      def generate_query
        secret = SecureRandom.random_bytes(4)

        params = {params:{rsa_key: @keys.public_key.to_pem}}
        json = JSON.generate(params).force_encoding("ASCII-8BIT")

        version = 2
        msgtype = 0
        op_code = 1
        msgsize = json.bytesize
        flagchr = 17
        padding = 0
        serials = secret.unpack1("N")
        crc_ini = 0x5a6b7c8d

        header = [version, msgtype, op_code,
                  msgsize, flagchr, padding,
                  serials, crc_ini].pack("CCSSCCNN")
        query = header + json

        crc = Zlib.crc32(query).to_s(16).rjust(8, '0').scan(/../).map {
          |x| x.to_i(16).chr
        }.join

        query[12, 4] = crc
        query
      end
    end
  end
end

# Example usage
if __FILE__ == $PROGRAM_NAME
  scanner = Tapocon::Scanner.new
  scanner.scan
end
