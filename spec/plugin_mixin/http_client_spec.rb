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
    expect(impl.client).to be_a(Manticore::Client)
  end

  it "#client should return the same client" do
    expect(impl.client).to eql(impl.client)
  end

  shared_examples "setting ca bundles" do |key|
    subject { Dummy.new(conf).client_config }

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
end
