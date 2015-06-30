# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/plugin_mixins/http_client"
require "stud/temporary"

class Dummy < LogStash::Inputs::Base
  include LogStash::PluginMixins::HttpClient
end

describe LogStash::PluginMixins::HttpClient do
  let(:basic_config) { {} }
  let(:impl) { Dummy.new(basic_config)  }

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

  shared_examples "setting ca bundles" do |key|
    subject { Dummy.new(conf).send(:client_config) }

    it "should correctly set the path" do
      expect(subject[:ssl][key]).to eql(path)
    end
  end

  describe "with a custom ssl bundle" do
    let(:file) { Stud::Temporary.file }
    let(:path) { file.path }
    after { File.unlink(path)}

    context "with x509" do
      let(:conf) { basic_config.merge("ca_path" => path) }

      include_examples("setting ca bundles", :ca_file)
    end

    context "with JKS" do
      let(:conf) { basic_config.merge("truststore_path" => path) }

      include_examples("setting ca bundles", :truststore)
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
end
