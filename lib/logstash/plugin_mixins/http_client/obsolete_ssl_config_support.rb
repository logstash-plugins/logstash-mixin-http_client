module LogStash::PluginMixins::HttpClient
  module ObsoleteSslConfigSupport
    def self.included(base)
      fail ArgumentError unless base <= LogStash::PluginMixins::HttpClient::Implementation

      require 'logstash/plugin_mixins/normalize_config_support'
      base.include(LogStash::PluginMixins::NormalizeConfigSupport)

      base.config :cacert, :obsolete => 'Use `ssl_certificate_authorities` instead'
      base.config :client_cert, :obsolete => 'Use `ssl_certificate` instead'
      base.config :client_key, :obsolete => 'Use `ssl_key` instead'
      base.config :keystore, :obsolete => 'Use `ssl_keystore_path` instead'
      base.config :keystore_type, :obsolete => 'Use `ssl_keystore_type` instead'
      base.config :truststore, :obsolete => 'Use `ssl_truststore_path` instead'
      base.config :truststore_type, :obsolete => 'Use `ssl_truststore_type` instead'

      # Retain validation for password types to avoid inadvertent information disclosure
      base.config :keystore_password, :validate => :password, :obsolete => 'Use `ssl_keystore_password` instead'
      base.config :truststore_password, :validate => :password, :obsolete => 'Use `ssl_truststore_password` instead'
    end
  end
end