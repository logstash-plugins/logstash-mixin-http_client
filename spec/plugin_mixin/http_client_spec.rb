# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/plugin_mixins/http_client"
require "stud/temporary"

class Dummy < LogStash::Inputs::Base
  include LogStash::PluginMixins::HttpClient
  config_name 'dummy'
end

describe LogStash::PluginMixins::HttpClient do
  let(:basic_config) { {} }
  let(:impl) { Dummy.new(basic_config) }

  it "should initialize with no extra settings" do
    expect {
      impl
    }.not_to raise_error
  end

  it "should create a client with defaults" do
    expect(impl.send(:make_client)).to be_a(Manticore::Client)
  end

  it "#client should return the client" do
    expect(impl.send(:client)).to be_a(Manticore::Client)
  end

  it "#client should return the same client" do
    expect(impl.send(:client)).to eql(impl.client)
  end

  shared_examples "setting ca bundles" do |key, type|
    subject { Dummy.new(conf).send(:client_config) }

    it "should correctly set the path" do
      expect(subject[:ssl][key]).to eql(path), "Expected to find path for #{key}"
    end

    if type == :jks
      let(:store_password) { conf["#{key}_password"] }
      let(:store_type) { conf["#{key}_type"]}

      it "should set the bundle password" do
        expect(subject[:ssl]["#{key}_password".to_sym]).to eql(store_password)
      end

      it "should set the bundle type" do
        expect(subject[:ssl]["#{key}_type".to_sym]).to eql(store_type)
      end
    end
  end

  shared_examples 'a deprecated setting with guidance' do |deprecations_and_guidance|

    let(:logger_stub) { double('Logger').as_null_object }

    before(:each) do
      allow(Dummy).to receive(:logger).and_return(logger_stub)
    end

    deprecations_and_guidance.each do |deprecated_setting_name, canonical_setting_name|
      it "emits a warning about the setting `#{deprecated_setting_name}` being deprecated and provides guidance to use `#{canonical_setting_name}`" do
        Dummy.new(conf)

        deprecation_text = "deprecated config setting \"#{deprecated_setting_name}\" set"
        guidance_text = "Use `#{canonical_setting_name}` instead"

        expect(logger_stub).to have_received(:warn).with(a_string_including(deprecation_text).and(including(guidance_text)), anything)
      end
    end
  end

  describe "with a custom ssl bundle" do
    let(:file) { Stud::Temporary.file }
    let(:path) { file.path }
    after { File.unlink(path)}

    context "with x509" do
      let(:conf) { basic_config.merge("cacert" => path) }

      include_examples("setting ca bundles", :ca_file)

      it_behaves_like('a deprecated setting with guidance',
                      'cacert' => 'ssl_certificate_authorities')
    end

    context "with JKS" do
      let(:conf) {
        basic_config.merge(
          "truststore" => path,
          "truststore_password" => "foobar",
          "truststore_type" => "jks"
        )
      }

      include_examples("setting ca bundles", :truststore, :jks)

      it_behaves_like('a deprecated setting with guidance',
                      'truststore' => 'ssl_truststore_path',
                      'truststore_password' => 'ssl_truststore_password',
                      'truststore_type' => 'ssl_truststore_type')
    end
  end

  describe "with a custom validate_after_activity" do
    subject { Dummy.new(client_config).send(:client_config) }

    let(:check_timeout) { 20 }
    let(:client_config) { basic_config.merge("validate_after_inactivity" => check_timeout )}

    it "should properly set the correct manticore option" do
      expect(subject[:check_connection_timeout]).to eql(check_timeout)
    end
  end

  describe "http auth" do
    subject { Dummy.new(client_config).send(:client_config)[:auth] }

    let(:user) { "myuser" }
    let(:password) { "mypassword" }
    let(:client_config) { basic_config.merge("user" => user, "password" => password )}

    it "should set the user correctly in the auth settings" do
      expect(subject[:user]).to eq(user)
    end

    it "should set the password correctly in the auth settings" do
      expect(subject[:password]).to eq(password)
    end

    it "should always enable eager auth" do
      expect(subject[:eager]).to eq(true)
    end

    context "with no user or password" do
      let(:client_config) { basic_config }

      it "should not set the auth parameter" do
        expect(subject).to be_nil
      end
    end

    context "with a user but no password specified" do
      let(:client_config) { c = super(); c.delete("password"); c }

      it "should raise a configuration error" do
        expect { subject }.to raise_error(::LogStash::ConfigurationError)
      end
    end
  end

  ["keystore", "truststore"].each do |store|
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
            Dummy.new(conf).client_config
          end.to raise_error(LogStash::ConfigurationError)
        end
      end
    end
  end

  describe "with a client cert" do
    let(:file) { Stud::Temporary.file }
    let(:path) { file.path }
    after { File.unlink(path)}

    context "with correct client certs" do
      let(:conf) { basic_config.merge("client_cert" => path, "client_key" => path) }

      it "should create without error" do
        expect {
          Dummy.new(conf).client_config
        }.not_to raise_error
      end

      it_behaves_like('a deprecated setting with guidance',
                      'client_cert' => 'ssl_certificate',
                      'client_key' => 'ssl_key')
    end

    shared_examples("raising a configuration error") do
      it "should raise an error error" do
        expect {
          Dummy.new(conf).client_config
        }.to raise_error(LogStash::PluginMixins::HttpClient::InvalidHTTPConfigError)
      end
    end

    context "without a key" do
      let(:conf) { basic_config.merge("client_cert" => path) }

      include_examples("raising a configuration error")
    end

    context "without a cert" do
      let(:conf) { basic_config.merge("client_key" => path) }

      include_examples("raising a configuration error")
    end
  end

  describe "with verify mode" do
    let(:file) { Stud::Temporary.file }
    let(:path) { file.path }
    after { File.unlink(path)}

    context "default" do
      let(:conf) { basic_config }

      it "sets manticore verify to :strict" do
        expect( Dummy.new(conf).client_config[:ssl] ).to include :verify => :strict
      end
    end

    context "'full'" do
      let(:conf) { basic_config.merge("ssl_verification_mode" => 'full') }

      it "sets manticore verify to :strict" do
        expect( Dummy.new(conf).client_config[:ssl] ).to include :verify => :strict
      end
    end

    context "'none'" do
      let(:conf) { basic_config.merge("ssl_verification_mode" => 'none') }

      it "sets manticore verify to :disable" do
        expect( Dummy.new(conf).client_config[:ssl] ).to include :verify => :disable
      end
    end

  end

  describe "with supported protocols" do
    context "default" do
      let(:conf) { basic_config }

      it "does not set manticore protocols option" do
        expect( Dummy.new(conf).client_config[:ssl] ).to_not include :protocols
      end
    end

    context "empty" do
      let(:conf) { basic_config.merge("ssl_supported_protocols" => []) }

      it "does not set manticore protocols option" do
        expect( Dummy.new(conf).client_config[:ssl] ).to_not include :protocols
      end
    end

    context "'TLSv1.3'" do
      let(:conf) { basic_config.merge("ssl_supported_protocols" => ['TLSv1.3']) }

      it "sets manticore protocols option" do
        expect( Dummy.new(conf).client_config[:ssl] ).to include :protocols => ['TLSv1.3']
      end
    end

    context "'TLSv1.2' and 'TLSv1.3'" do
      let(:conf) { basic_config.merge("ssl_supported_protocols" => ['TLSv1.3', 'TLSv1.2']) }

      it "sets manticore protocols option" do
        expect( Dummy.new(conf).client_config[:ssl] ).to include :protocols => ['TLSv1.3', 'TLSv1.2']
      end
    end

  end
end
