# encoding: utf-8
require "logstash/config/mixin"

# This module provides helper for the `AWS-SDK` v1,
# and it will be deprecated in the near future, please use the V2 module
# for any new development.
module LogStash::PluginMixins::HttpClient
  def self.included(base)
    require 'manticore'
    base.extend(self)
    base.setup_http_client_config
  end

  public
  def setup_http_client_config
    # Timeout (in seconds) for the entire request
    config :request_timeout, :validate => :number, :default => 60

    # Timeout (in seconds) to wait for data on the socket. Default is 10s
    config :socket_timeout, :validate => :number, :default => 10

    # Timeout (in seconds) to wait for a connection to be established. Default is 10s
    config :connect_timeout, :validate => :number, :default => 10

    # Should redirects be followed? Defaults to true
    config :follow_redirects, :validate => :boolean, :default => true

    # Max number of concurrent connections. Defaults to 50
    config :pool_max, :validate => :number, :default => 50

    # Max number of concurrent connections to a single host. Defaults to 25
    config :pool_max_per_route, :validate => :number, :default => 25

    # How many times should the client retry a failing URL? Default is 3
    config :automatic_retries, :validate => :number, :default => 3

    # If you need to use a custom X.509 CA (.pem certs) specify the path to that here
    config :ca_path, :validate => :path

    # If you need to use a custom keystore (.jks) specify that here
    config :truststore_path, :validate => :path

    # Specify the keystore password here.
    # Note, most .jks files created with keytool require a password!
    config :truststore_password, :validate => :string

    # Enable cookie support. With this enabled the client will persist cookies
    # across requests as a normal web browser would. Enabled by default
    config :cookies, :validate => :boolean, :default => true

    # If you'd like to use an HTTP proxy . This supports multiple configuration syntaxes:
    # 1. Proxy host in form: http://proxy.org:1234
    # 2. Proxy host in form: {host => "proxy.org", port => 80, scheme => 'http', user => 'username@host', password => 'password'}
    # 3. Proxy host in form: {url =>  'http://proxy.org:1234', user => 'username@host', password => 'password'}
    config :proxy
  end

  public
  def client_config
    c = {
      connect_timeout: @connect_timeout,
      socket_timeout: @socket_timeout,
      request_timeout: @request_timeout,
      follow_redirects: @follow_redirects,
      automatic_retries: @automatic_retries,
      pool_max: @pool_max,
      pool_max_per_route: @pool_max_per_route,
      cookies: @cookies,
    }

    if @proxy
      # Symbolize keys if necessary
      c[:proxy] = @proxy.is_a?(Hash) ?
        @proxy.reduce({}) {|memo,(k,v)| memo[k.to_sym] = v; memo} :
        @proxy
    end

    c[:ssl] = {}
    if @ca_path
      c[:ssl][:ca_file] = @ca_path
    end
    if (@truststore_path)
      c[:ssl].merge!(
        truststore: @truststore_path
      )

      # JKS files have optional passwords if programatically created
      if (@truststore_password)
        c[:ssl].merge!(truststore_password: @truststore_password)
      end
    end

    c
  end

  private
  def make_client
    Manticore::Client.new(client_config)
  end

  public
  def client
    @client ||= make_client
  end
end
