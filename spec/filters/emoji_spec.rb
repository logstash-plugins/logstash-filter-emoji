# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/emoji"

describe LogStash::Filters::Emoji do
  let(:config) { Hash.new }
  subject { described_class.new(config) }

  describe "user-defined match" do

    let(:config) do
      {
        "field"       => "status",
        "target"      => "foo",
        "sev_notice"  => "🆗"
      }
    end

    let(:event) { LogStash::Event.new("status" => "notice") }

    it "returns the selected emoji" do
      subject.register
      subject.filter(event)
      expect(event.get("foo")).to eq("🆗")
    end
  end

  describe "defalt severities" do

    let(:config) do
      {
        "field"       => "severity",
        "target"      => "foo"
      }
    end

    describe "emergency" do
      let(:event) { LogStash::Event.new("severity" => "0") }
      it "returns the default emoji" do
        subject.register
        subject.filter(event)
        expect(event.get("foo")).to eq("💥")
      end
    end

    describe "alert" do
      let(:event) { LogStash::Event.new("severity" => "1") }
      it "returns the default emoji" do
        subject.register
        subject.filter(event)
        expect(event.get("foo")).to eq("🚨")
      end
    end

    describe "critical" do
      let(:event) { LogStash::Event.new("severity" => "2") }
      it "returns the default emoji" do
        subject.register
        subject.filter(event)
        expect(event.get("foo")).to eq("🔥")
      end
    end

    describe "error" do
      let(:event) { LogStash::Event.new("severity" => "3") }
      it "returns the default emoji" do
        subject.register
        subject.filter(event)
        expect(event.get("foo")).to eq("❌")
      end
    end

    describe "warning" do
      let(:event) { LogStash::Event.new("severity" => "4") }
      it "returns the default emoji" do
        subject.register
        subject.filter(event)
        expect(event.get("foo")).to eq("⚠️")
      end
    end

    describe "notice" do
      let(:event) { LogStash::Event.new("severity" => "5") }
      it "returns the default emoji" do
        subject.register
        subject.filter(event)
        expect(event.get("foo")).to eq("👀")
      end
    end

    describe "informational" do
      let(:event) { LogStash::Event.new("severity" => "6") }
      it "returns the default emoji" do
        subject.register
        subject.filter(event)
        expect(event.get("foo")).to eq("ℹ️")
      end
    end

    describe "debug" do
      let(:event) { LogStash::Event.new("severity" => "7") }
      it "returns the default emoji" do
        subject.register
        subject.filter(event)
        expect(event.get("foo")).to eq("🐛")
      end
    end
  end

  describe "fallback value" do

    context "static configuration" do
      let(:config) do
        {
          "field"       => "status",
          "target"      => "foo",
          "fallback"    => "👀"
        }
      end

      let(:event) { LogStash::Event.new("status" => "200") }

      it "returns the fallback emoji" do
        subject.register
        subject.filter(event)
        expect(event.get("foo")).to eq("👀")
      end
    end

    context "allow sprintf" do
      let(:config) do
        {
          "field"    => "status",
          "target"   => "foo",
          "fallback" => "%{missing_match}"
        }
      end

      let(:event) { LogStash::Event.new("status" => "200", "missing_match" => "missing no match") }

      it "returns the sprintf string" do
        subject.register
        subject.filter(event)
        expect(event.get("foo")).to eq("missing no match")
      end
    end
  end
end
