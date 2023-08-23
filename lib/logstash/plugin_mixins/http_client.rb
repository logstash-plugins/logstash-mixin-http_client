# encoding: utf-8
require "logstash/config/mixin"

# This module makes it easy to add a very fully configured HTTP client to logstash
# based on [Manticore](https://github.com/cheald/manticore).
# For an example of its usage see https://github.com/logstash-plugins/logstash-input-http_poller
module LogStash::PluginMixins::HttpClient
  class InvalidHTTPConfigError < StandardError; end

  def self.[](**a)
    Adapter.new(**a)
  end

  def self.included(base)
    # TODO: deprecate the act of including this mixin directly,
    #       in a way that turns focus to plugin maintainers since
    #       an end-user cannot act to resolve the issue.
    base.include(Adapter.new(with_deprecated: true))
  end

  class Adapter < Module
    def initialize(with_deprecated: false)
      @include_dep = with_deprecated
    end

    def included(base)
      base.include(Implementation)
      if @include_dep
        require_relative 'http_client/deprecated_ssl_config_support'
        base.include(DeprecatedSslConfigSupport)
      end
      nil
    end
  end
  private_constant :Adapter

  module Implementation
    def self.included(base)
      require 'manticore'

      # Timeout (in seconds) for the entire request
      base.config :request_timeout, :validate => :number, :default => 60

      # Timeout (in seconds) to wait for data on the socket. Default is `10s`
      base.config :socket_timeout, :validate => :number, :default => 10

      # Timeout (in seconds) to wait for a connection to be established. Default is `10s`
      base.config :connect_timeout, :validate => :number, :default => 10

      # Should redirects be followed? Defaults to `true`
      base.config :follow_redirects, :validate => :boolean, :default => true

      # Max number of concurrent connections. Defaults to `50`
      base.config :pool_max, :validate => :number, :default => 50

      # Max number of concurrent connections to a single host. Defaults to `25`
      base.config :pool_max_per_route, :validate => :number, :default => 25

      # Turn this on to enable HTTP keepalive support. We highly recommend setting `automatic_retries` to at least
      # one with this to fix interactions with broken keepalive implementations.
      base.config :keepalive, :validate => :boolean, :default => true

      # How many times should the client retry a failing URL. We highly recommend NOT setting this value
      # to zero if keepalive is enabled. Some servers incorrectly end keepalives early requiring a retry!
      # Note: if `retry_non_idempotent` is set only GET, HEAD, PUT, DELETE, OPTIONS, and TRACE requests will be retried.
      base.config :automatic_retries, :validate => :number, :default => 1

      # If `automatic_retries` is enabled this will cause non-idempotent HTTP verbs (such as POST) to be retried.
      base.config :retry_non_idempotent, :validate => :boolean, :default => false

      # How long to wait before checking if the connection is stale before executing a request on a connection using keepalive.
      # # You may want to set this lower, possibly to 0 if you get connection errors regularly
      # Quoting the Apache commons docs (this client is based Apache Commmons):
      # 'Defines period of inactivity in milliseconds after which persistent connections must be re-validated prior to being leased to the consumer. Non-positive value passed to this method disables connection validation. This check helps detect connections that have become stale (half-closed) while kept inactive in the pool.'
      # See https://hc.apache.org/httpcomponents-client-ga/httpclient/apidocs/org/apache/http/impl/conn/PoolingHttpClientConnectionManager.html#setValidateAfterInactivity(int)[these docs for more info]
      base.config :validate_after_inactivity, :validate => :number, :default => 200

      # If you need to use a custom X.509 CA (.pem certs) specify the path to that here
      base.config :ssl_certificate_authorities, :validate => :path, :list => :true

      # If you'd like to use a client certificate (note, most people don't want this) set the path to the x509 cert here
      base.config :ssl_certificate, :validate => :path

      # If you're using a client certificate specify the path to the encryption key here
      base.config :ssl_key, :validate => :path

      # If you need to use a custom keystore (`.jks`) specify that here. This does not work with .pem keys!
      base.config :ssl_keystore_path, :validate => :path

      # Specify the keystore password here.
      # Note, most .jks files created with keytool require a password!
      base.config :ssl_keystore_password, :validate => :password

      # Specify the keystore type here. One of `jks` or `pkcs12`.
      # The default value is inferred from the filename.
      # Note: If it's unable to determine the type based on the filename, it uses the
      # `keystore.type` security property, or "jks" as default value.
      base.config :ssl_keystore_type, :validate => %w(pkcs12 jks)

      # Naming aligned with the Elastic stack.
      #   full: verifies that the provided certificate is signed by a trusted authority (CA) and also verifies that the
      #         server’s hostname (or IP address) matches the names identified within the certificate
      #   none: no verification of the server’s certificate
      base.config :ssl_verification_mode, :validate => ['full', 'none'], :default => 'full'

      # The list of cipher suites to use, listed by priorities.
      # Supported cipher suites vary depending on which version of Java is used.
      base.config :ssl_cipher_suites, :validate => :string, :list => true

      # NOTE: the default setting [] uses Java SSL engine defaults.
      base.config :ssl_supported_protocols, :validate => ['TLSv1.1', 'TLSv1.2', 'TLSv1.3'], :default => [], :list => true

      # If you need to use a custom truststore (`.jks`) specify that here. This does not work with .pem certs!
      base.config :ssl_truststore_path, :validate => :path

      # Specify the truststore password here.
      # Note, most .jks files created with keytool require a password!
      base.config :ssl_truststore_password, :validate => :password

      # Specify the truststore type here. One of `JKS` or `PKCS12`.
      # The default value is inferred from the filename.
      # Note: If it's unable to determine the type based on the filename, it uses the
      # `keystore.type` security property, or "jks" as default value.
      base.config :ssl_truststore_type, :validate => %w(pkcs12 jks)

      # Enable cookie support. With this enabled the client will persist cookies
      # across requests as a normal web browser would. Enabled by default
      base.config :cookies, :validate => :boolean, :default => true

      # If you'd like to use an HTTP proxy . This supports multiple configuration syntaxes:
      #
      # 1. Proxy host in form: `http://proxy.org:1234`
      # 2. Proxy host in form: `{host => "proxy.org", port => 80, scheme => 'http', user => 'username@host', password => 'password'}`
      # 3. Proxy host in form: `{url =>  'http://proxy.org:1234', user => 'username@host', password => 'password'}`
      base.config :proxy

      # Username to use for HTTP auth.
      base.config :user, :validate => :string

      # Password to use for HTTP auth
      base.config :password, :validate => :password
    end

    public

    def client_config
      c = {
        connect_timeout: @connect_timeout,
        socket_timeout: @socket_timeout,
        request_timeout: @request_timeout,
        follow_redirects: @follow_redirects,
        automatic_retries: @automatic_retries,
        retry_non_idempotent: @retry_non_idempotent,
        check_connection_timeout: @validate_after_inactivity,
        pool_max: @pool_max,
        pool_max_per_route: @pool_max_per_route,
        cookies: @cookies,
        keepalive: @keepalive
      }

      if @proxy
        # Symbolize keys if necessary
        c[:proxy] = @proxy.is_a?(Hash) ?
                      @proxy.reduce({}) {|memo,(k,v)| memo[k.to_sym] = v; memo} :
                      @proxy
      end

      if @user
        if !@password || !@password.value
          raise ::LogStash::ConfigurationError, "User '#{@user}' specified without password!"
        end

        # Symbolize keys if necessary
        c[:auth] = {
          :user => @user,
          :password => @password.value,
          :eager => true
        }
      end

      c[:ssl] = ssl_options

      c
    end

    private

    def ssl_options

      options = {}
      if @ssl_certificate_authorities&.any?
        raise LogStash::ConfigurationError, 'Multiple values on `ssl_certificate_authorities` are not supported by this plugin' if @ssl_certificate_authorities.size > 1

        options[:ca_file] = @ssl_certificate_authorities.first
      end

      if @ssl_truststore_path
        options[:truststore] = @ssl_truststore_path
        options[:truststore_type] = @ssl_truststore_type if @ssl_truststore_type
        options[:truststore_password] = @ssl_truststore_password.value if @ssl_truststore_password
      elsif @ssl_truststore_password
        fail LogStash::ConfigurationError, "truststore_password requires ssl_truststore_path you fool"
      end

      if @ssl_keystore_path
        options[:keystore] = @ssl_keystore_path
        options[:keystore_type] = @ssl_keystore_type if @ssl_keystore_type
        options[:keystore_password] = @ssl_keystore_password.value if @ssl_keystore_password
      elsif @ssl_keystore_password
        fail LogStash::ConfigurationError, "ssl_keystore_password requires ssl_keystore_path you fool"
      end

      if @ssl_certificate && @ssl_key
        options[:client_cert] = @ssl_certificate
        options[:client_key] = @ssl_key
      elsif !!@ssl_certificate ^ !!@ssl_key
        raise InvalidHTTPConfigError, "You must specify both `ssl_certificate` and `ssl_key` for an HTTP client, or neither!"
      end

      options[:verify] = @ssl_verification_mode == 'full' ? :strict : :disable
      options[:protocols] = @ssl_supported_protocols if @ssl_supported_protocols&.any?
      options[:cipher_suites] = @ssl_cipher_suites if @ssl_cipher_suites&.any?

      options
    end

    def make_client
      Manticore::Client.new(client_config)
    end

    public
    def client
      @client ||= make_client
    end
  end
end