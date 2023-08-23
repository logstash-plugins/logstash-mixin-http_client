module LogStash::PluginMixins::HttpClient
  module DeprecatedSslConfigSupport
    def self.included(base)
      fail ArgumentError unless base <= LogStash::PluginMixins::HttpClient::Implementation

      require 'logstash/plugin_mixins/normalize_config_support'
      base.include(LogStash::PluginMixins::NormalizeConfigSupport)

      # If you need to use a custom X.509 CA (.pem certs) specify the path to that here
      base.config :cacert, :validate => :path, :deprecated => 'Use `ssl_certificate_authorities` instead'
      # If you'd like to use a client certificate (note, most people don't want this) set the path to the x509 cert here
      base.config :client_cert, :validate => :path, :deprecated => 'Use `ssl_certificate` instead'
      # If you're using a client certificate specify the path to the encryption key here
      base.config :client_key, :validate => :path, :deprecated => 'Use `ssl_key` instead'
      # If you need to use a custom keystore (`.jks`) specify that here. This does not work with .pem keys!
      base.config :keystore, :validate => :path, :deprecated => 'Use `ssl_keystore_path` instead'
      # Specify the keystore password here.
      # Note, most .jks files created with keytool require a password!
      base.config :keystore_password, :validate => :password, :deprecated => 'Use `ssl_keystore_password` instead'
      # Specify the keystore type here. One of `JKS` or `PKCS12`. Default is `JKS`
      base.config :keystore_type, :validate => :string, :default => 'JKS', :deprecated => 'Use `ssl_keystore_type` instead'
      # If you need to use a custom truststore (`.jks`) specify that here. This does not work with .pem certs!
      base.config :truststore, :validate => :path, :deprecated => 'Use `ssl_truststore_path` instead'
      # Specify the truststore password here.
      # Note, most .jks files created with keytool require a password!
      base.config :truststore_password, :validate => :password, :deprecated => 'Use `ssl_truststore_password` instead'
      # Specify the truststore type here. One of `JKS` or `PKCS12`. Default is `JKS`
      base.config :truststore_type, :validate => :string, :default => 'JKS', :deprecated => 'Use `ssl_truststore_type` instead'
      # NOTE: the default setting [] uses Java SSL engine defaults.
    end

    def initialize(*a)
      super

      @ssl_certificate_authorities = normalize_config(:ssl_certificate_authorities) do |normalize|
        normalize.with_deprecated_mapping(:cacert) do |cacert|
          [cacert]
        end
      end

      params['ssl_certificate_authorities'] = @ssl_certificate_authorities unless @ssl_certificate_authorities.nil?

      @ssl_certificate = normalize_config(:ssl_certificate) do |normalize|
        normalize.with_deprecated_alias(:client_cert)
      end

      params['ssl_certificate'] = @ssl_certificate unless @ssl_certificate.nil?

      @ssl_key = normalize_config(:ssl_key) do |normalize|
        normalize.with_deprecated_alias(:client_key)
      end

      params['ssl_key'] = @ssl_key unless @ssl_key.nil?

      %w[keystore truststore].each do |store|
        %w[path type password].each do |variable|
          config_name = "ssl_#{store}_#{variable}"
          normalized_value = normalize_config(config_name) do |normalize|
            deprecated_config_alias = variable == 'path' ? store : "#{store}_#{variable}"
            normalize.with_deprecated_alias(deprecated_config_alias.to_sym)
          end
          instance_variable_set("@#{config_name}", normalized_value)
          params[config_name.to_s] = normalized_value unless normalized_value.nil?
        end
      end
    end

    def ssl_options
      fail(InvalidHTTPConfigError, "When `client_cert` is provided, `client_key` must also be provided") if @client_cert && !@client_key
      fail(InvalidHTTPConfigError, "A `client_key` is not allowed unless a `client_cert` is provided") if @client_key && !@client_cert

      fail(LogStash::ConfigurationError, "When `keystore` is provided, `keystore_password` must also be provided") if @keystore && !@keystore_password
      fail(LogStash::ConfigurationError, "A `keystore_password` is not allowed unless a `keystore` is provided") if @keystore_password && !@keystore

      fail(LogStash::ConfigurationError, "When `truststore` is provided, `truststore_password` must also be provided") if @truststore && !@truststore_password
      fail(LogStash::ConfigurationError, "A `truststore_password` is not allowed unless a `truststore` is provided") if @truststore_password && !@truststore

      super
    end
  end
end