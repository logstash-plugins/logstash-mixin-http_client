require 'logstash/devutils/rspec/spec_helper'
require 'logstash/plugin_mixins/http_client'
require 'logstash/plugin_mixins/http_client/deprecated_ssl_config_support'
require 'stud/temporary'

shared_examples 'setting ca bundles' do |key, type|
  subject(:client_config) { plugin_class.new(conf).send(:client_config) }

  it 'should correctly set the path' do
    expect(client_config[:ssl][key]).to eql(path), "Expected to find path for #{key}"
  end

  if type == :jks
    let(:store_password) { conf["#{use_deprecated_config ? '' : 'ssl_'}#{key}_password"] }
    let(:store_type) { conf["#{use_deprecated_config ? '' : 'ssl_'}#{key}_type"]}

    it 'should set the bundle password' do
      expect(client_config[:ssl]["#{key}_password".to_sym]).to eql(store_password)
    end

    it 'should set the bundle type' do
      expect(client_config[:ssl]["#{key}_type".to_sym]).to eql(store_type)
    end
  end
end

shared_examples 'a deprecated setting with guidance' do |deprecations_and_guidance|

  let(:logger_stub) { double('Logger').as_null_object }

  before(:each) do
    allow(plugin_class).to receive(:logger).and_return(logger_stub)
  end

  deprecations_and_guidance.each do |deprecated_setting_name, canonical_setting_name|
    it "emits a warning about the setting `#{deprecated_setting_name}` being deprecated and provides guidance to use `#{canonical_setting_name}`" do
      plugin_class.new(conf)

      deprecation_text = "deprecated config setting \"#{deprecated_setting_name}\" set"
      guidance_text = "Use `#{canonical_setting_name}` instead"

      expect(logger_stub).to have_received(:warn).with(a_string_including(deprecation_text).and(including(guidance_text)), anything)
    end
  end
end

shared_examples 'with common ssl options' do
  describe 'with verify mode' do
    let(:file) { Stud::Temporary.file }
    let(:path) { file.path }
    after { File.unlink(path)}

    context 'default' do
      let(:conf) { basic_config }

      it 'sets manticore verify to :strict' do
        expect(plugin_class.new(conf).client_config[:ssl]).to include :verify => :strict
      end
    end

    context "'full'" do
      let(:conf) { basic_config.merge('ssl_verification_mode' => 'full') }

      it 'sets manticore verify to :strict' do
        expect(plugin_class.new(conf).client_config[:ssl]).to include :verify => :strict
      end
    end

    context "'none'" do
      let(:conf) { basic_config.merge('ssl_verification_mode' => 'none') }

      it 'sets manticore verify to :disable' do
        expect(plugin_class.new(conf).client_config[:ssl]).to include :verify => :disable
      end
    end
  end

  describe 'with supported protocols' do
    context 'default' do
      let(:conf) { basic_config }

      it 'does not set manticore protocols option' do
        expect(plugin_class.new(conf).client_config[:ssl]).to_not include :protocols
      end
    end

    context 'empty' do
      let(:conf) { basic_config.merge('ssl_supported_protocols' => []) }

      it 'does not set manticore protocols option' do
        expect(plugin_class.new(conf).client_config[:ssl]).to_not include :protocols
      end
    end

    context "'TLSv1.3'" do
      let(:conf) { basic_config.merge('ssl_supported_protocols' => ['TLSv1.3']) }

      it 'sets manticore protocols option' do
        expect(plugin_class.new(conf).client_config[:ssl]).to include :protocols => ['TLSv1.3']
      end
    end

    context "'TLSv1.2' and 'TLSv1.3'" do
      let(:conf) { basic_config.merge('ssl_supported_protocols' => ['TLSv1.3', 'TLSv1.2']) }

      it 'sets manticore protocols option' do
        expect(plugin_class.new(conf).client_config[:ssl]).to include :protocols => ['TLSv1.3', 'TLSv1.2']
      end
    end
  end

  describe 'with ssl_cipher_suites' do
    context 'default' do
      let(:conf) { basic_config }

      it 'does not set manticore cipher_suites option' do
        expect(plugin_class.new(conf).client_config[:ssl]).to_not include :cipher_suites
      end
    end

    context 'empty' do
      let(:conf) { basic_config.merge('ssl_cipher_suites' => []) }

      it 'does not set manticore cipher_suites option' do
        expect(plugin_class.new(conf).client_config[:ssl]).to_not include :cipher_suites
      end
    end

    context "set to ['TLS_AES_256_GCM_SHA384']" do
      let(:conf) { basic_config.merge('ssl_cipher_suites' => ['TLS_AES_256_GCM_SHA384']) }

      it 'sets manticore cipher_suites option' do
        expect(plugin_class.new(conf).client_config[:ssl]).to include :cipher_suites => ['TLS_AES_256_GCM_SHA384']
      end
    end
  end
end

shared_examples("raise an http config error") do |message|
  it "should raise an error error" do
    expect {
      plugin_class.new(conf).client_config
    }.to raise_error(LogStash::PluginMixins::HttpClient::InvalidHTTPConfigError, message)
  end
end

shared_examples 'a client with deprecated ssl options' do
  describe LogStash::PluginMixins::HttpClient do
    let(:basic_config) { {} }
    let(:impl) { plugin_class.new(basic_config) }
    let(:use_deprecated_config) { true }

    include_examples 'with common ssl options'

    describe 'with a custom ssl bundle' do
      let(:file) { Stud::Temporary.file }
      let(:path) { file.path }
      after { File.unlink(path)}

      context 'with x509' do
        let(:conf) { basic_config.merge('cacert' => path) }

        include_examples('setting ca bundles', :ca_file)

        it_behaves_like('a deprecated setting with guidance',
          'cacert' => 'ssl_certificate_authorities')
      end

      context 'with JKS' do
        let(:conf) {
                     basic_config.merge(
                       'truststore' => path,
                       'truststore_password' => 'foobar',
                       'truststore_type' => 'jks'
                     )
                   }

        include_examples('setting ca bundles', :truststore, :jks)

        it_behaves_like('a deprecated setting with guidance',
          'truststore' => 'ssl_truststore_path',
          'truststore_password' => 'ssl_truststore_password',
          'truststore_type' => 'ssl_truststore_type')
      end
    end

    describe 'with a client cert' do
      let(:file) { Stud::Temporary.file }
      let(:path) { file.path }
      after { File.unlink(path)}

      context 'with correct client certs' do
        let(:conf) { basic_config.merge('client_cert' => path, 'client_key' => path) }

        it 'should create without error' do
          expect {
            plugin_class.new(conf).client_config
          }.not_to raise_error
        end

        it_behaves_like('a deprecated setting with guidance',
          'client_cert' => 'ssl_certificate',
          'client_key' => 'ssl_key')
      end

      context 'without a key' do
        let(:conf) { basic_config.merge('client_cert' => path) }

        include_examples('raise an http config error', 'When `client_cert` is provided, `client_key` must also be provided')
      end

      context 'without a cert' do
        let(:conf) { basic_config.merge('client_key' => path) }

        include_examples('raise an http config error', 'A `client_key` is not allowed unless a `client_cert` is provided')
      end
    end

    %w[keystore truststore].each do |store|
      describe "with a custom #{store}" do
        let(:file) { Stud::Temporary.file }
        let(:path) { file.path }
        let(:password) { "foo" }
        after { File.unlink(path)}

        let(:conf) {
                     basic_config.merge(
                       store => path,
                       "#{store}_password" => password,
                       "#{store}_type" => "jks"
                     ).compact
                   }

        include_examples("setting ca bundles", store.to_sym, :jks)

        it_behaves_like('a deprecated setting with guidance',
          "#{store}" => "ssl_#{store}_path",
          "#{store}_password" => "ssl_#{store}_password",
          "#{store}_type" => "ssl_#{store}_type")

        context "with no password set" do
          let(:password) { nil }

          it "should raise an error" do
            expect do
              plugin_class.new(conf).client_config
            end.to raise_error(LogStash::ConfigurationError)
          end
        end
      end
    end
  end
end

shared_examples 'a client with standardized ssl options' do
  describe LogStash::PluginMixins::HttpClient do
    let(:basic_config) { {} }
    let(:impl) { plugin_class.new(basic_config) }
    let(:use_deprecated_config) { false }

    include_examples 'with common ssl options'

    describe 'with a custom ssl bundle' do
      let(:file) { Stud::Temporary.file }
      let(:path) { file.path }
      after { File.unlink(path)}

      context 'with x509' do
        let(:conf) { basic_config.merge('ssl_certificate_authorities' => path) }

        include_examples('setting ca bundles', :ca_file)
      end

      context 'with JKS' do
        let(:conf) {
                     basic_config.merge(
                       'ssl_truststore_path' => path,
                       'ssl_truststore_password' => 'foobar',
                       'ssl_truststore_type' => 'jks'
                     )
                   }

        include_examples('setting ca bundles', :truststore, :jks)
      end
    end

    describe 'with a client cert' do
      let(:file) { Stud::Temporary.file }
      let(:path) { file.path }
      after { File.unlink(path)}

      context 'with correct client certs' do
        let(:conf) { basic_config.merge('ssl_certificate' => path, 'ssl_key' => path) }

        it 'should create without error' do
          expect {
            plugin_class.new(conf).client_config
          }.not_to raise_error
        end
      end

      context 'without an ssl_key' do
        let(:conf) { basic_config.merge('ssl_certificate' => path) }

        include_examples('raise an http config error', 'You must specify both `ssl_certificate` and `ssl_key` for an HTTP client, or neither!')
      end

      context 'without an ssl_certificate' do
        let(:conf) { basic_config.merge('ssl_key' => path) }
        include_examples('raise an http config error', 'You must specify both `ssl_certificate` and `ssl_key` for an HTTP client, or neither!')
      end
    end

    %w[keystore truststore].each do |store|
      describe "with a custom #{store}" do
        let(:file) { Stud::Temporary.file }
        let(:path) { file.path }
        let(:password) { "foo" }
        after { File.unlink(path)}

        let(:conf) {
                     basic_config.merge(
                       "ssl_#{store}_path" => path,
                       "ssl_#{store}_password" => password,
                       "ssl_#{store}_type" => "jks"
                     ).compact
                   }

        include_examples("setting ca bundles", store.to_sym, :jks)

        context "with no password set" do
          let(:password) { nil }

          it "should not raise an error" do
            expect do
              plugin_class.new(conf).client_config
            end.to_not raise_error
          end
        end
      end
    end
  end
end

class PluginWithNoModuleConfig < LogStash::Inputs::Base
  include LogStash::PluginMixins::HttpClient
  config_name 'no_config'
end

class PluginWithDeprecatedTrue < LogStash::Inputs::Base
  include LogStash::PluginMixins::HttpClient[:with_deprecated => true]
  config_name 'with_deprecated'
end

class PluginWithDeprecatedFalse < LogStash::Inputs::Base
  include LogStash::PluginMixins::HttpClient[:with_deprecated => false]
  config_name 'without_deprecated'
end

describe PluginWithNoModuleConfig do
  let(:plugin_class) { PluginWithNoModuleConfig }

  it_behaves_like 'a client with deprecated ssl options'

  it 'includes DeprecatedSslConfigSupport module' do
    expect(plugin_class.ancestors).to include(LogStash::PluginMixins::HttpClient::DeprecatedSslConfigSupport)
  end
end

describe PluginWithDeprecatedFalse do
  let(:plugin_class) { PluginWithDeprecatedFalse }

  it_behaves_like 'a client with standardized ssl options'

  it 'does not include DeprecatedSslConfigSupport module' do
    expect(plugin_class.ancestors).to_not include(LogStash::PluginMixins::HttpClient::DeprecatedSslConfigSupport)
  end
end

describe PluginWithDeprecatedTrue do
  let(:plugin_class) { PluginWithDeprecatedTrue }

  it_behaves_like 'a client with deprecated ssl options'

  it_behaves_like 'a client with standardized ssl options'

  context 'setting deprecate configs' do
    let(:cacert) { Stud::Temporary.file.path }
    let(:client_cert) { Stud::Temporary.file.path }
    let(:client_key) { Stud::Temporary.file.path }
    let(:keystore) { Stud::Temporary.file.path }
    let(:keystore_type) { 'pkcs12' }
    let(:keystore_password) { 'bar' }
    let(:truststore) { Stud::Temporary.file.path }
    let(:truststore_type) { 'pkcs12' }
    let(:truststore_password) { 'foo' }

    let(:settings) do
      {
        'cacert' => cacert,
        'client_cert' => client_cert,
        'client_key' => client_key,
        'keystore' => keystore,
        'keystore_password' => keystore_password,
        'keystore_type' => keystore_type,
        'truststore' => truststore,
        'truststore_password' => truststore_password,
        'truststore_type' => truststore_type
      }
    end

    subject(:plugin_instance) { plugin_class.new(settings) }

    after do
      File.unlink(cacert)
      File.unlink(client_cert)
      File.unlink(client_key)
      File.unlink(keystore)
      File.unlink(truststore)
    end

    it 'normalizes deprecated settings' do
      expect(plugin_instance.ssl_certificate_authorities).to eq([cacert])
      expect(plugin_instance.ssl_certificate).to eq(client_cert)
      expect(plugin_instance.ssl_key).to eq(client_key)
      expect(plugin_instance.ssl_keystore_path).to eq(keystore)
      expect(plugin_instance.ssl_keystore_password.value).to eq(keystore_password)
      expect(plugin_instance.ssl_keystore_type).to eq(keystore_type)
      expect(plugin_instance.ssl_truststore_path).to eq(truststore)
      expect(plugin_instance.ssl_truststore_password.value).to eq(truststore_password)
      expect(plugin_instance.ssl_truststore_type).to eq(truststore_type)
    end
  end

  it 'includes DeprecatedSslConfigSupport module' do
    expect(plugin_class.ancestors).to include(LogStash::PluginMixins::HttpClient::DeprecatedSslConfigSupport)
  end
end