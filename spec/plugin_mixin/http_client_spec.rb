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
end
